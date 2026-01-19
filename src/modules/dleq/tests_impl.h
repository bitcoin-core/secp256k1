/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_DLEQ_TESTS_H
#define SECP256K1_MODULE_DLEQ_TESTS_H

#include "dleq_vectors.h"
#include "../../unit_test.h"

static void dleq_nonce_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes) {
    secp256k1_scalar k1, k2;
    CHECK(secp256k1_dleq_nonce(&k1, args[0], args[1], args[2], args[3], args[4]) == 1);
    testrand_flip(args[n_flip], n_bytes);
    CHECK(secp256k1_dleq_nonce(&k2, args[0], args[1], args[2], args[3], args[4]) == 1);
    CHECK(secp256k1_scalar_eq(&k1, &k2) == 0);
}

static void run_test_dleq_prove_verify(void) {
    secp256k1_scalar s, e, a, k;
    secp256k1_ge A, B, C;
    unsigned char *args[5];
    unsigned char a32[32];
    unsigned char A_33[33];
    unsigned char C_33[33];
    unsigned char aux_rand[32];
    unsigned char msg[32];
    unsigned char proof_64[64] = {0};
    int i;
    int overflow;
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;
    unsigned char aux_tag[] = {'B', 'I', 'P', '0', '3', '7', '4', '/', 'a', 'u', 'x'};
    unsigned char tag[] = {'B', 'I', 'P', '0', '3', '7', '4', '/', 'n', 'o', 'n', 'c', 'e'};
    unsigned char challenge_tag[] = {'B', 'I', 'P', '0', '3', '7', '4', '/', 'c', 'h', 'a', 'l', 'l', 'e', 'n', 'g', 'e'};

    /* Check that hash initialized by secp256k1_nonce_function_bip374_sha256_tagged_aux has the expected state. */
    secp256k1_sha256_initialize_tagged(&sha, aux_tag, sizeof(aux_tag));
    secp256k1_nonce_function_bip374_sha256_tagged_aux(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

    /* Check that hash initialized by secp256k1_nonce_function_bip374_sha256_tagged has the expected state. */
    secp256k1_sha256_initialize_tagged(&sha, tag, sizeof(tag));
    secp256k1_nonce_function_bip374_sha256_tagged(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

    /* Check that hash initialized by secp256k1_dleq_sha256_tagged has the expected state. */
    secp256k1_sha256_initialize_tagged(&sha, challenge_tag, sizeof(challenge_tag));
    secp256k1_dleq_sha256_tagged(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

    for (i = 0; i < COUNT; i++) {
        testutil_random_ge_test(&B);
        testutil_random_scalar_order(&a);
        testrand256(aux_rand);
        testrand_bytes_test(msg, sizeof(msg));
        secp256k1_dleq_pair(&CTX->ecmult_gen_ctx, &A, &C, &a, &B);
        CHECK(secp256k1_dleq_prove_internal(CTX, &s, &e, &a, &B, &A, &C, aux_rand, (i & 1) ? msg : NULL) == 1);
        CHECK(secp256k1_dleq_verify_internal(&s, &e, &A, &B, &C, (i & 1) ? msg : NULL) == 1);
        secp256k1_scalar_set_b32(&s, proof_64, &overflow);
        VERIFY_CHECK(overflow == 0);
        secp256k1_scalar_set_b32(&e, proof_64 + 32, &overflow);
        VERIFY_CHECK(overflow == 0);
    }

    {
        secp256k1_scalar tmp;
        secp256k1_scalar_set_int(&tmp, 1);
        CHECK(secp256k1_dleq_verify_internal(&tmp, &e, &A, &B, &C, msg) == 0);
        CHECK(secp256k1_dleq_verify_internal(&s, &tmp, &A, &B, &C, msg) == 0);
    }
    {
        secp256k1_ge p_tmp;
        testutil_random_ge_test(&p_tmp);
        CHECK(secp256k1_dleq_verify_internal(&s, &e, &p_tmp, &B, &C, msg) == 0);
        CHECK(secp256k1_dleq_verify_internal(&s, &e, &A, &p_tmp, &C, msg) == 0);
        CHECK(secp256k1_dleq_verify_internal(&s, &e, &A, &B, &p_tmp, msg) == 0);
    }
    {
        secp256k1_ge p_inf;
        secp256k1_ge_set_infinity(&p_inf);
        CHECK(secp256k1_dleq_prove_internal(CTX, &s, &e, &a, &p_inf, &A, &C, aux_rand, msg) == 0);
        CHECK(secp256k1_dleq_prove_internal(CTX, &s, &e, &a, &B, &p_inf, &C, aux_rand, msg) == 0);
        CHECK(secp256k1_dleq_prove_internal(CTX, &s, &e, &a, &B, &A, &p_inf, aux_rand, msg) == 0);
    }

    /* Nonce tests */
    secp256k1_scalar_get_b32(a32, &a);
    secp256k1_eckey_pubkey_serialize33(&A, A_33);
    secp256k1_eckey_pubkey_serialize33(&C, C_33);
    CHECK(secp256k1_dleq_nonce(&k, a32, A_33, C_33, aux_rand, msg) == 1);

    testrand_bytes_test(a32, sizeof(a32));
    testrand_bytes_test(A_33, sizeof(A_33));
    testrand_bytes_test(C_33, sizeof(C_33));
    testrand_bytes_test(aux_rand, sizeof(aux_rand));

    /* Check that a bitflip in an argument results in different nonces. */
    args[0] = a32;
    args[1] = A_33;
    args[2] = C_33;
    args[3] = aux_rand;
    args[4] = msg;
    for (i = 0; i < COUNT; i++) {
        dleq_nonce_bitflip(args, 0, sizeof(a32));
        dleq_nonce_bitflip(args, 1, sizeof(A_33));
        /* Flip C */
        dleq_nonce_bitflip(args, 2, sizeof(C_33));
        /* Flip C again */
        dleq_nonce_bitflip(args, 2, sizeof(C_33));
        dleq_nonce_bitflip(args, 3, sizeof(aux_rand));
        dleq_nonce_bitflip(args, 4, sizeof(msg));
    }

    /* NULL aux_rand and msg arguments are allowed.*/
    CHECK(secp256k1_dleq_nonce(&k, a32, A_33, C_33, NULL, NULL) == 1);
    CHECK(secp256k1_dleq_nonce(&k, a32, A_33, C_33, aux_rand, NULL) == 1);
    CHECK(secp256k1_dleq_nonce(&k, a32, A_33, C_33, NULL, msg) == 1);
}

/* Test BIP-374 test vectors ("Discrete Log Equality Proofs").
 * See tools/test_vectors_dleq_generate.py
 * */

static unsigned char zero_array[32] = {0x00};

/* Helper function to check if given array is NOT equivalent to all zero array.
 * Used to detect test vectors where zero array can represent:
 *     B_bytes at infinity
 *     Empty optional msg_bytes
 * */
static int is_not_empty(const unsigned char *arr){
    return (memcmp(arr, zero_array, 32) != 0);
}

static void run_test_dleq_bip374_vectors(void) {
    secp256k1_scalar a, s, e;
    secp256k1_ge A;
    secp256k1_ge B;
    secp256k1_ge C;
    int i;

    /* bip-0374/test_vectors_generate_proof.csv */
    for (i = 0; i < 6; ++i) {
        int ret = 1;
        const unsigned char *m = NULL;
        secp256k1_ge_set_infinity(&B);
        /* expect the last 3 generate proof vectors to fail */
        if (i > 2) ret = 0;

        secp256k1_scalar_set_b32(&a, a_bytes[i], NULL);
        if (is_not_empty(B_bytes[i])) {
            CHECK(secp256k1_eckey_pubkey_parse(&B, B_bytes[i], 33) == 1);
        }

        secp256k1_dleq_pair(&CTX->ecmult_gen_ctx, &A, &C, &a, &B);

        if (is_not_empty(msg_bytes[i])) {
            m = msg_bytes[i];
        }
        CHECK(secp256k1_dleq_prove_internal(CTX, &s, &e, &a, &B, &A, &C, (unsigned char*)(auxrand_bytes[i]), m) == ret);

        if (ret) {
            unsigned char proof[64];
            secp256k1_scalar_get_b32(proof, &e);
            secp256k1_scalar_get_b32(proof + 32, &s);
            CHECK(memcmp(proof, proof_bytes[i], 64) == 0);
            CHECK(secp256k1_dleq_verify_internal(&s, &e, &A, &B, &C, m) == 1);
        }
    }

    /* bip-0374/test_vectors_verify_proof.csv */
    for (i = 0; i < 13; ++i) {
        const unsigned char *m = NULL;

        if (i > 2 && i < 6) {
            /* Skip tests indices 3-5: proof generation failure cases (a=0, a=N, B=infinity).
            * These contain placeholder data from test_vectors_generate_proof.csv that would
            * fail to parse. Only indices 0-2 and 6-12 have valid test data.
            * */
            continue;
        }

        CHECK(secp256k1_eckey_pubkey_parse(&A, A_bytes[i], 33) == 1);
        CHECK(secp256k1_eckey_pubkey_parse(&B, B_bytes[i], 33) == 1);
        CHECK(secp256k1_eckey_pubkey_parse(&C, C_bytes[i], 33) == 1);

        secp256k1_scalar_set_b32(&e, proof_bytes[i], NULL);
        secp256k1_scalar_set_b32(&s, proof_bytes[i] + 32, NULL);

        if (is_not_empty(msg_bytes[i])) {
            m = msg_bytes[i];
        }

        CHECK(secp256k1_dleq_verify_internal(&s, &e, &A, &B, &C, m) == success[i]);
    }
}

static void run_test_dleq_api(void) {
    secp256k1_pubkey B, A, C;
    unsigned char seckey[32];
    unsigned char proof[64];
    unsigned char aux_rand[32];
    unsigned char msg[32];
    secp256k1_scalar a;
    secp256k1_ge A_ge, B_ge, C_ge;

    /* Generate prove material */
    testrand256(seckey);
    testrand256(aux_rand);
    testrand256(msg);
    testutil_random_ge_test(&B_ge);
    secp256k1_pubkey_save(&B, &B_ge);

    /* Check dleq prove input validation */
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_dleq_prove(STATIC_CTX, proof, seckey, &B, aux_rand, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_prove(CTX, NULL, seckey, &B, aux_rand, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_prove(CTX, proof, NULL, &B, aux_rand, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_prove(CTX, proof, seckey, NULL, aux_rand, msg));
    CHECK(secp256k1_dleq_prove(CTX, proof, seckey, &B, NULL, msg) == 1);
    CHECK(secp256k1_dleq_prove(CTX, proof, seckey, &B, aux_rand, NULL) == 1);

    /* Generate verify material */
    secp256k1_scalar_set_b32(&a, seckey, NULL);
    secp256k1_dleq_pair(&CTX->ecmult_gen_ctx, &A_ge, &C_ge, &a, &B_ge);
    secp256k1_pubkey_save(&A, &A_ge);
    secp256k1_pubkey_save(&C, &C_ge);

    /* Check dleq verify input validation */
    CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, NULL, &A, &B, &C, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, proof, NULL, &B, &C, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, proof, &A, NULL, &C, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, proof, &A, &B, NULL, msg));
    /* Verify rejects an invalid (all-zero) proof */
    memset(proof, 0, sizeof(proof));
    CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &C, msg) == 0);

    /* Verify public API prove and verify functions */
    CHECK(secp256k1_dleq_prove(CTX, proof, seckey, &B, aux_rand, msg) == 1);
    CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &C, msg) == 1);
    CHECK(secp256k1_dleq_prove(CTX, proof, seckey, &B, NULL, NULL) == 1);
    CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &C, NULL) == 1);
}

static const struct tf_test_entry tests_dleq[] = {
    CASE(test_dleq_prove_verify),
    CASE(test_dleq_bip374_vectors),
    CASE(test_dleq_api),
};

#endif /* SECP256K1_MODULE_DLEQ_TESTS_H */
