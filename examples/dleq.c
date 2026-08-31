/*************************************************************************
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_dleq.h>
#include <secp256k1_ecdh.h>

#include "examples_util.h"

/* An ECDH "hash" function that does not hash. It outputs the shared point
 * itself in compressed form (33 bytes). */
static int ecdh_hash_function_compressed_point(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    (void)data;
    output[0] = (y32[31] & 1) ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN;
    memcpy(output + 1, x32, 32);
    return 1;
}

/* This example demonstrates a discrete log equality (DLEQ) proof as specified
 * in BIP-374, between two components of one sender's wallet. Alice is sending
 * to Bob, and Alice's wallet is split in two:
 *
 *   signer:      Alice's hardware wallet. Holds the secret key a and produces
 *                the proof.
 *   coordinator: Alice's watch-only wallet. Never sees a, and verifies the
 *                proof.
 *
 * The signer holds a secret key a with public key A = a*G, the key behind an
 * input Alice controls. It also derives C = a*B, where B is Bob's Silent
 * Payments scan public key (BIP-352), so C is the ECDH shared secret that
 * motivates BIP-374. Only the signer can compute C, and the coordinator
 * cannot recompute it to check, so without a proof it would have to take C on
 * trust and could build outputs paying the wrong script. The proof shows C
 * came from the same a as A, the input public key the coordinator already
 * knows. Verifying needs only public data A, B, C and the proof. */

/* Bob's Silent Payments scan public key, from the BIP-352 test vectors also
 * used in examples/silentpayments.c. This example only uses the decoded
 * scan public key. */
static const unsigned char recipient_scan_pubkey_bytes[33] = {
    0x02, 0x15, 0x40, 0xae, 0xa8, 0x97, 0x54, 0x7a,
    0xd4, 0x39, 0xb4, 0xe0, 0xf6, 0x09, 0xe5, 0xf0,
    0xfa, 0x63, 0xde, 0x89, 0xab, 0x11, 0xed, 0xe3,
    0x1e, 0x8c, 0xde, 0x4b, 0xe2, 0x19, 0x42, 0x5f, 0x23
};

int main(void) {
    unsigned char signer_seckey_a[32];
    unsigned char aux_rand[32];
    unsigned char randomize[32];
    unsigned char proof[64];
    int return_val, is_proof_valid;
    secp256k1_pubkey signer_pubkey_A;
    secp256k1_pubkey recipient_scan_pubkey_B;
    secp256k1_pubkey ecdh_share_point_C;
    unsigned char ecdh_share_point_C_ser[33];

    /* Before we can call actual API functions, we need to create a "context" */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return EXIT_FAILURE;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage. See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail. */
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    /*** Key Generation ***/
    {
        if (!fill_random(signer_seckey_a, sizeof(signer_seckey_a))) {
            printf("Failed to generate randomness\n");
            return EXIT_FAILURE;
        }
        /* If the secret key is zero or out of range (greater than secp256k1's
         * order), fail. Note that the probability of this happening is
         * negligible. */
        if (!secp256k1_ec_seckey_verify(ctx, signer_seckey_a)) {
            printf("Generated secret key is invalid.\n");
            return EXIT_FAILURE;
        }

        /* The signer's public key A = a*G. Public key creation using a valid
         * context with a verified secret key should never fail. */
        return_val = secp256k1_ec_pubkey_create(ctx, &signer_pubkey_A, signer_seckey_a);
        assert(return_val);
    }

    /*** Proof Generation (Alice's hardware signer) ***/
    {
        /* Bob's scan public key B, parsed from already-public data the same way
         * a real Silent Payments address would be used. */
        return_val = secp256k1_ec_pubkey_parse(ctx, &recipient_scan_pubkey_B, recipient_scan_pubkey_bytes, sizeof(recipient_scan_pubkey_bytes));
        assert(return_val);

        /* The signer derives C = a*B from its secret key and the recipient's
         * scan public key, the point BIP-374 proves the statement about.
         * BIP-352 goes one step further: its ECDH shared secret is
         * input_hash*a*B, so C is that value without the input_hash factor.
         * We use secp256k1_ecdh rather than secp256k1_ec_pubkey_tweak_mul
         * because it treats the secret key as secret and runs in constant
         * time, with a hash function that returns the point unhashed. This
         * should never fail with a verified secret key and valid pubkey. */
        return_val = secp256k1_ecdh(ctx, ecdh_share_point_C_ser, &recipient_scan_pubkey_B, signer_seckey_a, ecdh_hash_function_compressed_point, NULL);
        assert(return_val);
        return_val = secp256k1_ec_pubkey_parse(ctx, &ecdh_share_point_C, ecdh_share_point_C_ser, sizeof(ecdh_share_point_C_ser));
        assert(return_val);

        /* BIP-374 recommends fresh auxiliary randomness for each proof. This
         * argument is optional and may be NULL. */
        if (!fill_random(aux_rand, sizeof(aux_rand))) {
            printf("Failed to generate randomness\n");
            return EXIT_FAILURE;
        }

        /* Generate a proof that A and C were derived from the same secret key a,
         * without revealing a.
         *
         * Proof generation with a verified secret key and valid pubkey should
         * never fail. */
        return_val = secp256k1_dleq_prove(ctx, proof, signer_seckey_a, &recipient_scan_pubkey_B, aux_rand, NULL);
        assert(return_val);

        printf("Proof: ");
        print_hex(proof, sizeof(proof));

        /* The signer is done: we clear its secrets and destroy its context
         * here, before verifying, to show that verification needs neither
         * secret material nor a signing-capable context. */
        secure_erase(signer_seckey_a, sizeof(signer_seckey_a));
        secure_erase(aux_rand, sizeof(aux_rand));
        secp256k1_context_destroy(ctx);
    }

    /*** Proof Verification (Alice's watch-only coordinator) ***/
    {
        /* The coordinator verifies the proof using only A, B, C and the proof:
         * it never needs the signer's secret key, which we just erased.
         * Verification needs no precomputed generator table, so it also works
         * with the static (i.e., global) context secp256k1_context_static. See
         * its description in include/secp256k1.h for details. */
        is_proof_valid = secp256k1_dleq_verify(secp256k1_context_static, proof, &signer_pubkey_A, &recipient_scan_pubkey_B, &ecdh_share_point_C, NULL);

        if (is_proof_valid) {
            printf("Coordinator knows A and C share the same scalar a.\n");
        } else {
            printf("Coordinator should alert user of tampering.\n");
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}
