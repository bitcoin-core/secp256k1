/**********************************************************************
 * Copyright (c) 2018 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

/**
 * This file demonstrates how to use the aggsig module to sign a message
 * with multiple keys and aggregate the result into a single signature.
 * Additionally, see the documentation in include/secp256k1_aggsig.h.
 *
 * Note that you need to pass the --enable-module-aggsig to configure
 * in order to build this example.
 */

#include <stdio.h>
#include <assert.h>

#include <secp256k1.h>
#include <secp256k1_aggsig.h>

/* Number of public keys involved in creating the aggregate signature */
#define N_PUBKEYS 3

/* Create a key pair and store it in seckey and pubkey */
int create_key(const secp256k1_context* ctx, unsigned char* seckey, secp256k1_pubkey* pubkey) {
    int ret;
    FILE *frand = fopen("/dev/urandom", "r");
    do {
        if (frand == NULL || !fread(seckey, 32, 1, frand)) {
            return 0;
        }
    /* The probability that this not a valid secret key is approximately 2^-128 */
    } while (!secp256k1_ec_seckey_verify(ctx, seckey));

    ret = secp256k1_ec_pubkey_create(ctx, pubkey, seckey);
    assert(ret);
    fclose(frand);
    return 1;
}

/* Sign a message hash with the given key pairs and store the result in sig */
int sign(const secp256k1_context* ctx, unsigned char seckeys[][32], const secp256k1_pubkey* pubkeys, const unsigned char* msghash, unsigned char* sig) {
    FILE *frand;
    unsigned char secseed[32];
    secp256k1_aggsig_context* aggctx;
    int i;
    secp256k1_aggsig_partial_signature partial_signatures[N_PUBKEYS];

    /* Creating an aggsig context requires FRESH RANDOMNESS for the RNG seed.
     * The seed must be kept SECRET. */
    frand = fopen("/dev/urandom", "r");
    if (frand == NULL || !fread(secseed, 32, 1, frand)) {
        return 0;
    }
    fclose(frand);

    /* Create an aggsig context to initialize the nonce RNG and manage the aggsig state machine */
    aggctx = secp256k1_aggsig_context_create(ctx, pubkeys, N_PUBKEYS, secseed);

    /* Generate a nonce for each public key involved */
    for (i = 0; i < N_PUBKEYS; i++) {
        if (!secp256k1_aggsig_generate_nonce(ctx, aggctx, i)) {
            return 0;
        }
    }
    /* Sign with each key */
    for (i = 0; i < N_PUBKEYS; i++) {
        if (!secp256k1_aggsig_partial_sign(ctx, aggctx, &partial_signatures[i], msghash, seckeys[i], i)) {
            return 0;
        }
    }
    /* Combine partial signatures into sig */
    if (!secp256k1_aggsig_combine_signatures(ctx, aggctx, sig, partial_signatures)) {
        return 0;
    }

    secp256k1_aggsig_context_destroy(aggctx);
    return 1;
}

/* Verify an aggregated signature of pubkeys over msghash */
int verify(const secp256k1_context* ctx, const unsigned char *sig, const unsigned char *msghash, const secp256k1_pubkey *pubkeys) {
    /* Create "scratch space" to allocate memory for the aggsig verification
     * algorithm. But first, compute the optimal size of the space. */
    size_t scratch_size = secp256k1_aggsig_verify_scratch_size(N_PUBKEYS);
    secp256k1_scratch_space* scratch;
    /* The scratch space can be limited or set to a fixed size. If it's smaller
     * than the optimum, then the verification algorithm will run slower. But
     * the scratch space must fit at least one public key. */
    if (scratch_size > 9000) {
        scratch_size = 9000;
    }
    scratch = secp256k1_scratch_space_create(ctx, 0, scratch_size);
    if (scratch == NULL) {
        return 0;
    }

    if (!secp256k1_aggsig_verify(ctx, scratch, sig, msghash, pubkeys, N_PUBKEYS)) {
        return 0;
    }
    secp256k1_scratch_space_destroy(scratch);
    return 1;
}

int main(void) {
    secp256k1_context* ctx;
    int i;
    unsigned char seckeys[N_PUBKEYS][32];
    secp256k1_pubkey pubkeys[N_PUBKEYS];
    unsigned char msghash[32] = "this_should_actually_be_msg_hash";
    unsigned char sig[64];

    /* Create a context for signing and verification */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    printf("Creating key pairs....");
    for (i = 0; i < N_PUBKEYS; i++) {
        if (!create_key(ctx, seckeys[i], &pubkeys[i])) {
            printf("FAILED\n");
            return 1;
        }
    }
    printf("ok\n");

    printf("Signing message.......");
    if (!sign(ctx, seckeys, pubkeys, msghash, sig)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");

    printf("Verifying signature...");
    if (!verify(ctx, sig, msghash, pubkeys)) {
        printf("FAILED\n");
        return 1;
    }
    printf("ok\n");

    secp256k1_context_destroy(ctx);
    return 0;
}
