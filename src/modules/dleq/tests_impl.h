/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_DLEQ_TESTS_H
#define SECP256K1_MODULE_DLEQ_TESTS_H

#include "vectors.h"
#include "../../unit_test.h"

static void dleq_nonce_bitflip(unsigned char **args, size_t n_flip, size_t n_bytes) {
    secp256k1_scalar k1, k2;
    CHECK(secp256k1_dleq_nonce(&CTX->hash_ctx, &k1, args[0], args[1], args[2], args[3], args[4]) == 1);
    testrand_flip(args[n_flip], n_bytes);
    CHECK(secp256k1_dleq_nonce(&CTX->hash_ctx, &k2, args[0], args[1], args[2], args[3], args[4]) == 1);
    CHECK(secp256k1_scalar_eq(&k1, &k2) == 0);
}

static void dleq_sha256_zeros(uint32_t *state, const unsigned char *blocks64, size_t n_blocks) {
    (void)blocks64;
    (void)n_blocks;
    memset(state, 0, 8 * sizeof(*state));
}

static void run_test_dleq_prove_verify(void) {
    secp256k1_scalar e, s, a, k;
    secp256k1_ge A, B, C;
    unsigned char *args[5];
    unsigned char a32[32];
    unsigned char A_33[33];
    unsigned char C_33[33];
    unsigned char aux_rand[32];
    unsigned char msg[32];
    int i;
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;
    unsigned char aux_tag[] = {'B', 'I', 'P', '0', '3', '7', '4', '/', 'a', 'u', 'x'};
    unsigned char tag[] = {'B', 'I', 'P', '0', '3', '7', '4', '/', 'n', 'o', 'n', 'c', 'e'};
    unsigned char challenge_tag[] = {'B', 'I', 'P', '0', '3', '7', '4', '/', 'c', 'h', 'a', 'l', 'l', 'e', 'n', 'g', 'e'};

    /* Check that hash initialized by secp256k1_nonce_function_bip374_sha256_tagged_aux has the expected state. */
    secp256k1_sha256_initialize_tagged(&CTX->hash_ctx, &sha, aux_tag, sizeof(aux_tag));
    secp256k1_nonce_function_bip374_sha256_tagged_aux(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

    /* Check that hash initialized by secp256k1_nonce_function_bip374_sha256_tagged has the expected state. */
    secp256k1_sha256_initialize_tagged(&CTX->hash_ctx, &sha, tag, sizeof(tag));
    secp256k1_nonce_function_bip374_sha256_tagged(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

    /* Check that hash initialized by secp256k1_dleq_sha256_tagged has the expected state. */
    secp256k1_sha256_initialize_tagged(&CTX->hash_ctx, &sha, challenge_tag, sizeof(challenge_tag));
    secp256k1_dleq_sha256_tagged(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);

    for (i = 0; i < COUNT; i++) {
        const unsigned char *msg32;

        testutil_random_ge_test(&B);
        testutil_random_scalar_order(&a);
        testrand256(aux_rand);
        testrand_bytes_test(msg, sizeof(msg));
        msg32 = (i & 1) ? msg : NULL;
        secp256k1_dleq_pair(&CTX->ecmult_gen_ctx, &A, &C, &a, &B);
        CHECK(secp256k1_dleq_prove_internal(CTX, &e, &s, &a, &A, &B, &C, aux_rand, msg32) == 1);
        CHECK(secp256k1_dleq_verify_internal(&CTX->hash_ctx, &e, &s, &A, &B, &C, msg32) == 1);

        /* Tampering with any scalar or point invalidates the proof. */
        {
            secp256k1_scalar tmp;
            secp256k1_scalar_set_int(&tmp, 1);
            CHECK(secp256k1_dleq_verify_internal(&CTX->hash_ctx, &tmp, &s, &A, &B, &C, msg32) == 0);
            CHECK(secp256k1_dleq_verify_internal(&CTX->hash_ctx, &e, &tmp, &A, &B, &C, msg32) == 0);
        }
        {
            secp256k1_ge p_tmp;
            testutil_random_ge_test(&p_tmp);
            CHECK(secp256k1_dleq_verify_internal(&CTX->hash_ctx, &e, &s, &p_tmp, &B, &C, msg32) == 0);
            CHECK(secp256k1_dleq_verify_internal(&CTX->hash_ctx, &e, &s, &A, &p_tmp, &C, msg32) == 0);
            CHECK(secp256k1_dleq_verify_internal(&CTX->hash_ctx, &e, &s, &A, &B, &p_tmp, msg32) == 0);
        }
    }

    /* Infinity checks */
    {
        secp256k1_ge p_inf;
        secp256k1_ge_set_infinity(&p_inf);
        CHECK(secp256k1_dleq_prove_internal(CTX, &e, &s, &a, &p_inf, &B, &C, aux_rand, msg) == 0);
        CHECK(secp256k1_dleq_prove_internal(CTX, &e, &s, &a, &A, &p_inf, &C, aux_rand, msg) == 0);
        CHECK(secp256k1_dleq_prove_internal(CTX, &e, &s, &a, &A, &B, &p_inf, aux_rand, msg) == 0);
    }
    {
        secp256k1_ge A_gen = secp256k1_ge_const_g;
        secp256k1_ge A_neg = secp256k1_ge_const_g;
        secp256k1_scalar_set_int(&e, 1);
        secp256k1_scalar_set_int(&s, 1);
        /* R1 = s*G - e*A is infinity when A = G and e = s = 1. */
        CHECK(secp256k1_dleq_verify_internal(&CTX->hash_ctx, &e, &s, &A_gen, &B, &C, msg) == 0);
        /* R2 = s*B - e*C is infinity when C = B. A = -G keeps R1 = 2G finite. */
        secp256k1_ge_neg(&A_neg, &A_neg);
        CHECK(secp256k1_dleq_verify_internal(&CTX->hash_ctx, &e, &s, &A_neg, &B, &B, msg) == 0);
    }

    /* Proof generation fails when nonce generation produces zero. */
    {
        secp256k1_context *ctx = secp256k1_context_clone(CTX);
        ctx->hash_ctx.fn_sha256_compression = dleq_sha256_zeros;
        CHECK(secp256k1_dleq_prove_internal(ctx, &e, &s, &a, &A, &B, &C, aux_rand, msg) == 0);
        secp256k1_context_destroy(ctx);
    }

    /* Nonce tests */
    secp256k1_scalar_get_b32(a32, &a);
    secp256k1_ge_serialize_ext33(A_33, &A);
    secp256k1_ge_serialize_ext33(C_33, &C);
    CHECK(secp256k1_dleq_nonce(&CTX->hash_ctx, &k, a32, A_33, C_33, aux_rand, msg) == 1);

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
        dleq_nonce_bitflip(args, 2, sizeof(C_33));
        dleq_nonce_bitflip(args, 3, sizeof(aux_rand));
        dleq_nonce_bitflip(args, 4, sizeof(msg));
    }

    /* NULL aux_rand and msg arguments are allowed. */
    CHECK(secp256k1_dleq_nonce(&CTX->hash_ctx, &k, a32, A_33, C_33, NULL, NULL) == 1);
    CHECK(secp256k1_dleq_nonce(&CTX->hash_ctx, &k, a32, A_33, C_33, aux_rand, NULL) == 1);

    /* Check that the precomputed ZERO_MASK used for a NULL aux_rand argument
     * matches passing 32 zero bytes as aux_rand. */
    {
        unsigned char aux_rand_zero[32] = { 0 };
        secp256k1_scalar k_zero;

        CHECK(secp256k1_dleq_nonce(&CTX->hash_ctx, &k, a32, A_33, C_33, NULL, msg) == 1);
        CHECK(secp256k1_dleq_nonce(&CTX->hash_ctx, &k_zero, a32, A_33, C_33, aux_rand_zero, msg) == 1);
        CHECK(secp256k1_scalar_eq(&k, &k_zero));
    }
}

static void run_test_dleq_bip374_vectors(void) {
    secp256k1_pubkey A, B, C, output_pubkey_C;
    unsigned char proof[64];
    size_t i;

    for (i = 0; i < ARRAY_SIZE(dleq_generate_vectors); ++i) {
        const struct dleq_generate_vector *vector = &dleq_generate_vectors[i];
        const unsigned char *msg32 = vector->has_message ? vector->message : NULL;

        /* The public API cannot express B at infinity. prove_internal's
         * rejection of it is tested in run_test_dleq_prove_verify. */
        if (vector->point_B_is_infinity) {
            continue;
        }
        CHECK(secp256k1_ec_pubkey_parse(CTX, &B, vector->point_B, sizeof(vector->point_B)) == 1);

        CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, vector->scalar_a, &B, vector->auxrand, msg32) == vector->expected_success);
        if (vector->expected_success) {
            CHECK(memcmp(proof, vector->expected_proof, sizeof(proof)) == 0);
            CHECK(secp256k1_ec_pubkey_create(CTX, &A, vector->scalar_a) == 1);
            /* The proof verifies against the returned output_pubkey_C */
            CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &output_pubkey_C, msg32) == 1);
        }
    }

    for (i = 0; i < ARRAY_SIZE(dleq_verify_vectors); ++i) {
        const struct dleq_verify_vector *vector = &dleq_verify_vectors[i];
        const unsigned char *msg32 = vector->has_message ? vector->message : NULL;

        CHECK(secp256k1_ec_pubkey_parse(CTX, &A, vector->point_A, sizeof(vector->point_A)) == 1);
        CHECK(secp256k1_ec_pubkey_parse(CTX, &B, vector->point_B, sizeof(vector->point_B)) == 1);
        CHECK(secp256k1_ec_pubkey_parse(CTX, &C, vector->point_C, sizeof(vector->point_C)) == 1);

        CHECK(secp256k1_dleq_verify(CTX, vector->proof, &A, &B, &C, msg32) == vector->expected_success);
    }
}

static void run_test_dleq_api(void) {
    secp256k1_pubkey A, B, output_pubkey_C;
    const secp256k1_pubkey zero_pubkey = { 0 };
    unsigned char seckey[32];
    unsigned char proof[64];
    unsigned char aux_rand[32];
    unsigned char msg[32];
    secp256k1_ge B_ge;

    /* Generate prove material */
    testrand256(seckey);
    testrand256(aux_rand);
    testrand256(msg);
    testutil_random_ge_test(&B_ge);
    secp256k1_pubkey_save(&B, &B_ge);

    /* Check dleq prove input validation */
    memset(proof, 0xfe, sizeof(proof));
    memset(&output_pubkey_C, 0xfe, sizeof(output_pubkey_C));
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_dleq_prove(STATIC_CTX, proof, &output_pubkey_C, seckey, &B, aux_rand, msg));
    CHECK(secp256k1_memcmp_var(&output_pubkey_C, &zero_pubkey, sizeof(output_pubkey_C)) == 0);
    CHECK(secp256k1_is_zero_array(proof, sizeof(proof)));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_prove(CTX, NULL, &output_pubkey_C, seckey, &B, aux_rand, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_prove(CTX, proof, NULL, seckey, &B, aux_rand, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, NULL, &B, aux_rand, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, seckey, NULL, aux_rand, msg));
    CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, seckey, &B, NULL, msg) == 1);
    CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, seckey, &B, aux_rand, NULL) == 1);
    {
        secp256k1_pubkey invalid_pubkey = { 0 };
        memset(proof, 0xfe, sizeof(proof));
        memset(&output_pubkey_C, 0xfe, sizeof(output_pubkey_C));
        CHECK_ILLEGAL(CTX, secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, seckey, &invalid_pubkey, aux_rand, msg));
        CHECK(secp256k1_memcmp_var(&output_pubkey_C, &zero_pubkey, sizeof(output_pubkey_C)) == 0);
        CHECK(secp256k1_is_zero_array(proof, sizeof(proof)));
    }
    {
        unsigned char invalid_seckey[32] = { 0 };
        /* Test invalid secret key handling */
        memset(proof, 0xfe, sizeof(proof));
        memset(&output_pubkey_C, 0xfe, sizeof(output_pubkey_C));
        CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, invalid_seckey, &B, aux_rand, msg) == 0);
        CHECK(secp256k1_memcmp_var(&output_pubkey_C, &zero_pubkey, sizeof(output_pubkey_C)) == 0);
        CHECK(secp256k1_is_zero_array(proof, sizeof(proof)));
        memcpy(invalid_seckey, secp256k1_group_order_bytes, sizeof(invalid_seckey));
        memset(proof, 0xfe, sizeof(proof));
        memset(&output_pubkey_C, 0xfe, sizeof(output_pubkey_C));
        CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, invalid_seckey, &B, aux_rand, msg) == 0);
        CHECK(secp256k1_memcmp_var(&output_pubkey_C, &zero_pubkey, sizeof(output_pubkey_C)) == 0);
        CHECK(secp256k1_is_zero_array(proof, sizeof(proof)));
    }

    /* Generate verify material */
    CHECK(secp256k1_ec_pubkey_create(CTX, &A, seckey) == 1);
    CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, seckey, &B, aux_rand, msg) == 1);

    /* Check dleq verify input validation */
    CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, NULL, &A, &B, &output_pubkey_C, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, proof, NULL, &B, &output_pubkey_C, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, proof, &A, NULL, &output_pubkey_C, msg));
    CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, proof, &A, &B, NULL, msg));
    {
        secp256k1_pubkey invalid_pubkey = { 0 };
        CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, proof, &invalid_pubkey, &B, &output_pubkey_C, msg));
        CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, proof, &A, &invalid_pubkey, &output_pubkey_C, msg));
        CHECK_ILLEGAL(CTX, secp256k1_dleq_verify(CTX, proof, &A, &B, &invalid_pubkey, msg));
    }

    /* Verify rejects an e or s that overflows the group order */
    CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, seckey, &B, NULL, NULL) == 1);
    memcpy(&proof[0], secp256k1_group_order_bytes, 32);
    CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &output_pubkey_C, NULL) == 0);
    CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, seckey, &B, NULL, NULL) == 1);
    memcpy(&proof[32], secp256k1_group_order_bytes, 32);
    CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &output_pubkey_C, NULL) == 0);

    /* A proof over a message verifies only against that message */
    CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, seckey, &B, aux_rand, msg) == 1);
    CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &output_pubkey_C, msg) == 1);
    CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &output_pubkey_C, NULL) == 0);
    {
        unsigned char wrong_msg[32];
        testrand256(wrong_msg);
        CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &output_pubkey_C, wrong_msg) == 0);
    }

    /* A proof over no message does not verify against a message */
    CHECK(secp256k1_dleq_prove(CTX, proof, &output_pubkey_C, seckey, &B, NULL, NULL) == 1);
    CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &output_pubkey_C, NULL) == 1);
    CHECK(secp256k1_dleq_verify(CTX, proof, &A, &B, &output_pubkey_C, msg) == 0);

    /* Verification needs no precomputed generator table */
    CHECK(secp256k1_dleq_verify(STATIC_CTX, proof, &A, &B, &output_pubkey_C, NULL) == 1);

    {
        secp256k1_context *ctx = secp256k1_context_clone(CTX);
        ctx->hash_ctx.fn_sha256_compression = dleq_sha256_zeros;
        memset(proof, 0xfe, sizeof(proof));
        memset(&output_pubkey_C, 0xfe, sizeof(output_pubkey_C));
        CHECK(secp256k1_dleq_prove(ctx, proof, &output_pubkey_C, seckey, &B, aux_rand, msg) == 0);
        CHECK(secp256k1_memcmp_var(&output_pubkey_C, &zero_pubkey, sizeof(output_pubkey_C)) == 0);
        CHECK(secp256k1_is_zero_array(proof, sizeof(proof)));
        secp256k1_context_destroy(ctx);
    }
}

static const struct tf_test_entry tests_dleq[] = {
    CASE(test_dleq_prove_verify),
    CASE(test_dleq_bip374_vectors),
    CASE(test_dleq_api),
};

#endif /* SECP256K1_MODULE_DLEQ_TESTS_H */
