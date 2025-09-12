/*************************************************************************
 * Written in 2025 by Fabian Jahr                                        *
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

/** This file demonstrates how to use the FullAgg module to create an
 *  aggregate signature where each signer signs a different message.
 *  
 *  FullAgg (DahLIAS) allows multiple signers to create a single aggregate
 *  signature that proves each signer signed their respective message.
 */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_schnorrsig_fullagg.h>

#include "examples_util.h"

#define N_SIGNERS 3

struct signer_secrets {
    secp256k1_keypair keypair;
    secp256k1_fullagg_secnonce secnonce;
};

struct signer {
    secp256k1_pubkey pubkey;
    secp256k1_fullagg_pubnonce pubnonce;
    secp256k1_fullagg_partial_sig partial_sig;
    unsigned char message[32];
};

/* Create a key pair, store it in signer_secrets->keypair and signer->pubkey */
static int create_keypair(const secp256k1_context* ctx, struct signer_secrets *signer_secrets, struct signer *signer) {
    unsigned char seckey[32];

    if (!fill_random(seckey, sizeof(seckey))) {
        printf("Failed to generate randomness\n");
        return 0;
    }
    /* Try to create a keypair with a valid context. This only fails if the
     * secret key is zero or out of range (greater than secp256k1's order). Note
     * that the probability of this occurring is negligible with a properly
     * functioning random number generator. */
    if (!secp256k1_keypair_create(ctx, &signer_secrets->keypair, seckey)) {
        return 0;
    }
    if (!secp256k1_keypair_pub(ctx, &signer->pubkey, &signer_secrets->keypair)) {
        return 0;
    }

    secure_erase(seckey, sizeof(seckey));
    return 1;
}

static void setup_messages(struct signer *signers) {
    memset(signers[0].message, 0, 32);
    memset(signers[1].message, 0, 32);
    memset(signers[2].message, 0, 32);
    memcpy(signers[0].message, "jonas", 5);
    memcpy(signers[1].message, "tim", 3);
    memcpy(signers[2].message, "yannick", 7);
}

/* Each signer generates their nonce pair (R1_i, R2_i) */
static int nonce_generation_round(const secp256k1_context* ctx, 
                                  struct signer_secrets *signer_secrets,
                                  struct signer *signers) {
    int i;
    for (i = 0; i < N_SIGNERS; i++) {
        unsigned char seckey[32];
        unsigned char session_secrand[32];
        
        /* Create random session ID. It is absolutely necessary that the session ID
         * is unique for every call of secp256k1_fullagg_nonce_gen. Otherwise
         * it's trivial for an attacker to extract the secret key! */
        if (!fill_random(session_secrand, sizeof(session_secrand))) {
            return 0;
        }
        if (!secp256k1_keypair_sec(ctx, seckey, &signer_secrets[i].keypair)) {
            return 0;
        }
        
        /* Initialize session and create secret nonce for signing and public
         * nonce to send to the coordinator. Each signer provides their own
         * message here, which binds the nonce to their specific message. */
        if (!secp256k1_fullagg_nonce_gen(ctx, &signer_secrets[i].secnonce, &signers[i].pubnonce, 
                                         session_secrand, seckey, &signers[i].pubkey, 
                                         signers[i].message, NULL)) {
            return 0;
        }

        secure_erase(seckey, sizeof(seckey));
    }
    return 1;
}

/* Each signer creates their partial signature */
static int partial_signing_round(const secp256k1_context* ctx,
                                 struct signer_secrets *signer_secrets,
                                 struct signer *signers,
                                 const secp256k1_fullagg_session *session,
                                 const secp256k1_pubkey **pubkeys,
                                 const unsigned char **messages,
                                 const secp256k1_fullagg_pubnonce **pubnonces) {
    int i;
    for (i = 0; i < N_SIGNERS; i++) {
        /* Each signer computes their partial signature:
         * - First computes their challenge c_i = H_sig(L, R, X_i, m_i) where L is the list of all (Xi, mi) pairs
         * - Then computes s_i = r1_i + b*r2_i + c_i*x_i
         * The partial_sign function will clear the secnonce by setting it to 0. That's because
         * you must _never_ reuse the secnonce. If you do, you effectively reuse the nonce and
         * leak the secret key. */
        if (!secp256k1_fullagg_partial_sign(ctx, &signers[i].partial_sig, 
                                           &signer_secrets[i].secnonce, 
                                           &signer_secrets[i].keypair, 
                                           session, pubkeys, messages, 
                                           pubnonces, i)) {
            return 0;
        }
    }
    return 1;
}

/* Verify each partial signature individually */
static int verify_partial_signatures(const secp256k1_context* ctx,
                                     struct signer *signers,
                                     const secp256k1_fullagg_session *session,
                                     const secp256k1_pubkey **pubkeys,
                                     const unsigned char **messages) {
    int i;
    /* The coordinator can optionally verify each partial signature individually
     * before aggregating them. This helps identify which signer(s) may have 
     * produced invalid signatures if the aggregate signature fails to verify. */
    for (i = 0; i < N_SIGNERS; i++) {
        if (!secp256k1_fullagg_partial_sig_verify(ctx, &signers[i].partial_sig, 
                                                  &signers[i].pubnonce, 
                                                  &signers[i].pubkey, 
                                                  session, pubkeys, messages, i)) {
            printf("Partial signature %d failed to verify\n", i);
            return 0;
        }
    }
    return 1;
}

int main(void) {
    secp256k1_context* ctx;
    int i;
    struct signer_secrets signer_secrets[N_SIGNERS];
    struct signer signers[N_SIGNERS];
    const secp256k1_pubkey *pubkeys[N_SIGNERS];
    const unsigned char *messages[N_SIGNERS];
    const secp256k1_fullagg_pubnonce *pubnonces[N_SIGNERS];
    const secp256k1_fullagg_partial_sig *partial_sigs[N_SIGNERS];
    secp256k1_fullagg_session session;
    secp256k1_fullagg_aggnonce agg_pubnonce;
    unsigned char sig[64];

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    
    printf("\n=== Running FullAgg Example ===\n");
    printf("Creating a single signature for %d signers with different messages\n\n", N_SIGNERS);

    printf("Signers: Creating key pairs... ");
    fflush(stdout);
    for (i = 0; i < N_SIGNERS; i++) {
        if (!create_keypair(ctx, &signer_secrets[i], &signers[i])) {
            printf("FAILED\n");
            return EXIT_FAILURE;
        }
        pubkeys[i] = &signers[i].pubkey;
    }
    printf("ok\n");

    printf("Signers: Setting up messages... ");
    fflush(stdout);
    setup_messages(signers);
    for (i = 0; i < N_SIGNERS; i++) {
        messages[i] = signers[i].message;
    }
    printf("ok\n");

    printf("Signers: Generating nonces... ");
    fflush(stdout);
    /* In FullAgg, we use two nonces per signer to prevent rogue-key attacks
     * without requiring a proof of possession. */
    if (!nonce_generation_round(ctx, signer_secrets, signers)) {
        printf("FAILED\n");
        return EXIT_FAILURE;
    }
    for (i = 0; i < N_SIGNERS; i++) {
        pubnonces[i] = &signers[i].pubnonce;
    }
    printf("ok\n");

    printf("Coordinator: Aggregating nonces... ");
    fflush(stdout);
    /* The coordinator (can be any party) collects all public nonces and
     * aggregates them: R1 = sum(R1_i), R2 = sum(R2_i) */
    if (!secp256k1_fullagg_nonce_agg(ctx, &agg_pubnonce, pubnonces, N_SIGNERS)) {
        printf("FAILED\n");
        return EXIT_FAILURE;
    }
    printf("ok\n");

    printf("All: Initializing session... ");
    fflush(stdout);
    /* The session computes:
     * - The nonce coefficient b = H_non(R1, R2, all Xi, all mi, all R2_i)
     * - The final nonce R = R1 + b*R2
     * This binds the final nonce to all signers' keys, messages, and individual nonces. */
    if (!secp256k1_fullagg_session_init(ctx, &session, &agg_pubnonce, 
                                        pubkeys, messages, pubnonces, N_SIGNERS)) {
        printf("FAILED\n");
        return EXIT_FAILURE;
    }
    printf("ok\n");

    printf("Signers: Creating partial signatures... ");
    fflush(stdout);
    if (!partial_signing_round(ctx, signer_secrets, signers, &session, 
                               pubkeys, messages, pubnonces)) {
        printf("FAILED\n");
        return EXIT_FAILURE;
    }
    for (i = 0; i < N_SIGNERS; i++) {
        partial_sigs[i] = &signers[i].partial_sig;
    }
    printf("ok\n");

    printf("Coordinator: Verifying partial signatures... ");
    fflush(stdout);
    if (!verify_partial_signatures(ctx, signers, &session, pubkeys, messages)) {
        printf("FAILED\n");
        return EXIT_FAILURE;
    }
    printf("ok\n");

    printf("Coordinator: Aggregating signatures... ");
    fflush(stdout);
    /* The final signature is (R, s) where s = sum(s_i) */
    if (!secp256k1_fullagg_partial_sig_agg(ctx, sig, &session, partial_sigs, N_SIGNERS)) {
        printf("FAILED\n");
        return EXIT_FAILURE;
    }
    printf("ok\n");

    printf("All: Verifying aggregate signature... ");
    fflush(stdout);
    /* Verify the aggregate signature against all public keys and their messages.
     * The verification checks that s*G = R + sum(c_i*X_i) where each c_i is
     * computed from the specific message m_i that signer i signed. */
    if (!secp256k1_fullagg_verify(ctx, sig, pubkeys, messages, N_SIGNERS)) {
        printf("FAILED\n");
        return EXIT_FAILURE;
    }
    printf("ok\n");
    
    /* Test that the signature is specific to these exact messages */
    printf("Testing message binding... ");
    fflush(stdout);
    
    /* Modify one message to verify the signature is bound to specific messages */
    signers[1].message[0] ^= 0xFF;
    
    if (secp256k1_fullagg_verify(ctx, sig, pubkeys, messages, N_SIGNERS)) {
        printf("FAILED (signature verified with modified message)\n");
        return EXIT_FAILURE;
    }
    
    /* Restore the original message and verify it works again */
    signers[1].message[0] ^= 0xFF;
    
    if (!secp256k1_fullagg_verify(ctx, sig, pubkeys, messages, N_SIGNERS)) {
        printf("FAILED (signature doesn't verify after restoring)\n");
        return EXIT_FAILURE;
    }
    printf("ok\n");

    printf("\nFinal Aggregate Signature: ");
    for (i = 0; i < 64; i++) {
        printf("%02x", sig[i]);
        if (i == 31) printf(" ");
    }
    printf("\n");
    
    /* It's best practice to try to clear secrets from memory after using them.
     * This is done because some bugs can allow an attacker to leak memory, for
     * example through "out of bounds" array access (see Heartbleed), or the OS
     * swapping them to disk. Hence, we overwrite secret key material with zeros.
     *
     * Here we are preventing these writes from being optimized out, as any good compiler
     * will remove any writes that aren't used. */
    for (i = 0; i < N_SIGNERS; i++) {
        secure_erase(&signer_secrets[i], sizeof(signer_secrets[i]));
    }
    secp256k1_context_destroy(ctx);
    return EXIT_SUCCESS;
}
