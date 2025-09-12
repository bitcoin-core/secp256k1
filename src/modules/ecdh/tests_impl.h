/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ECDH_TESTS_H
#define SECP256K1_MODULE_ECDH_TESTS_H

static int ecdh_hash_function_test_xpassthru(unsigned char *output, const unsigned char *x, const unsigned char *y, void *data) {
    (void)y;
    (void)data;
    memcpy(output, x, 32);
    return 1;
}

static int ecdh_hash_function_test_fail(unsigned char *output, const unsigned char *x, const unsigned char *y, void *data) {
    (void)output;
    (void)x;
    (void)y;
    (void)data;
    return 0;
}

static int ecdh_xonly_hash_function_test_fail(unsigned char *output, const unsigned char *x, void *data) {
    (void)output;
    (void)x;
    (void)data;
    return 0;
}

static int ecdh_hash_function_custom(unsigned char *output, const unsigned char *x, const unsigned char *y, void *data) {
    (void)data;
    /* Save x and y as uncompressed public key */
    output[0] = 0x04;
    memcpy(output + 1, x, 32);
    memcpy(output + 33, y, 32);
    return 1;
}

static int ecdh_xonly_hash_function_custom(unsigned char *output, const unsigned char *x, void *data) {
    (void)data;
    /* Output X coordinate. */
    memcpy(output, x, 32);
    return 1;
}

static void test_ecdh_api(void) {
    secp256k1_pubkey point;
    unsigned char res[32];
    unsigned char x32[32];
    unsigned char s_one[32] = { 0 };
    s_one[31] = 1;

    CHECK(secp256k1_ec_pubkey_create(CTX, &point, s_one) == 1);

    /* Check all NULLs are detected */
    CHECK(secp256k1_ecdh(CTX, res, &point, s_one, NULL, NULL) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_ecdh(CTX, NULL, &point, s_one, NULL, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_ecdh(CTX, res, NULL, s_one, NULL, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_ecdh(CTX, res, &point, NULL, NULL, NULL));
    CHECK(secp256k1_ecdh(CTX, res, &point, s_one, NULL, NULL) == 1);

    /* And the same for secp256k1_ecdh_xonly. */
    memset(x32, 131, 32); /* sum(131*256^j, j=0..31) is a valid x coordinate. */
    CHECK(secp256k1_ecdh_xonly(CTX, res, x32, s_one, NULL, NULL) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_ecdh_xonly(CTX, NULL, x32, s_one, NULL, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_ecdh_xonly(CTX, res, NULL, s_one, NULL, NULL));
    CHECK_ILLEGAL(CTX, secp256k1_ecdh_xonly(CTX, res, x32, NULL, NULL, NULL));
    CHECK(secp256k1_ecdh_xonly(CTX, res, x32, s_one, NULL, NULL) == 1);
    memset(x32, 205, 32); /* sum(205*256^j, j=0..31) is not a valid x coordinate. */
    CHECK(secp256k1_ecdh_xonly(CTX, res, x32, s_one, NULL, NULL) == 0);
}

static void test_ecdh_generator_basepoint(void) {
    unsigned char s_one[32] = { 0 };
    unsigned char x32_g[32];
    secp256k1_pubkey point[2];
    int i;

    s_one[31] = 1;
    CHECK(secp256k1_ec_pubkey_create(CTX, &point[0], s_one) == 1);
    secp256k1_fe_get_b32(x32_g, &secp256k1_ge_const_g.x);

    /* Check against pubkey creation when the basepoint is the generator */
    for (i = 0; i < 2 * COUNT; ++i) {
        secp256k1_sha256 sha;
        unsigned char s_b32[32];
        unsigned char output_ecdh[65];
        unsigned char output_ser[32];
        unsigned char point_ser[65];
        size_t point_ser_len = sizeof(point_ser);
        secp256k1_scalar s;

        testutil_random_scalar_order(&s);
        secp256k1_scalar_get_b32(s_b32, &s);

        CHECK(secp256k1_ec_pubkey_create(CTX, &point[1], s_b32) == 1);

        /* compute using ECDH function with custom hash function */
        CHECK(secp256k1_ecdh(CTX, output_ecdh, &point[0], s_b32, ecdh_hash_function_custom, NULL) == 1);
        /* compute "explicitly" */
        CHECK(secp256k1_ec_pubkey_serialize(CTX, point_ser, &point_ser_len, &point[1], SECP256K1_EC_UNCOMPRESSED) == 1);
        /* compare */
        CHECK(secp256k1_memcmp_var(output_ecdh, point_ser, 65) == 0);

        /* Do the same with x-only ECDH. */
        CHECK(secp256k1_ecdh_xonly(CTX, output_ecdh, x32_g, s_b32, ecdh_xonly_hash_function_custom, NULL) == 1);
        /* compare */
        CHECK(secp256k1_memcmp_var(output_ecdh, point_ser + 1, 32) == 0);

        /* compute using ECDH function with default hash function */
        CHECK(secp256k1_ecdh(CTX, output_ecdh, &point[0], s_b32, NULL, NULL) == 1);
        /* compute "explicitly" */
        CHECK(secp256k1_ec_pubkey_serialize(CTX, point_ser, &point_ser_len, &point[1], SECP256K1_EC_COMPRESSED) == 1);
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, point_ser, point_ser_len);
        secp256k1_sha256_finalize(&sha, output_ser);
        /* compare */
        CHECK(secp256k1_memcmp_var(output_ecdh, output_ser, 32) == 0);

        /* And the same with x-only ECDH. */
        CHECK(secp256k1_ecdh_xonly(CTX, output_ecdh, x32_g, s_b32, NULL, NULL) == 1);
        /* compute "explicitly" */
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, point_ser +1 , 32);
        secp256k1_sha256_finalize(&sha, output_ser);
        /* compare */
        CHECK(secp256k1_memcmp_var(output_ecdh, output_ser, 32) == 0);
    }
}

static void test_bad_scalar(void) {
    unsigned char s_zero[32] = { 0 };
    unsigned char s_overflow[32] = {
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
        0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xfe,
        0xba, 0xae, 0xdc, 0xe6, 0xaf, 0x48, 0xa0, 0x3b,
        0xbf, 0xd2, 0x5e, 0x8c, 0xd0, 0x36, 0x41, 0x41
    };
    unsigned char s_rand[32] = { 0 };
    unsigned char output[32];
    unsigned char point_ser[33];
    secp256k1_scalar rand;
    secp256k1_pubkey point;
    size_t point_ser_len = sizeof(point_ser);

    /* Create random point */
    testutil_random_scalar_order(&rand);
    secp256k1_scalar_get_b32(s_rand, &rand);
    CHECK(secp256k1_ec_pubkey_create(CTX, &point, s_rand) == 1);
    CHECK(secp256k1_ec_pubkey_serialize(CTX, point_ser, &point_ser_len, &point, SECP256K1_EC_COMPRESSED) == 1);

    /* Try to multiply it by bad values */
    CHECK(secp256k1_ecdh(CTX, output, &point, s_zero, NULL, NULL) == 0);
    CHECK(secp256k1_ecdh(CTX, output, &point, s_overflow, NULL, NULL) == 0);
    /* ...and a good one */
    s_overflow[31] -= 1;
    CHECK(secp256k1_ecdh(CTX, output, &point, s_overflow, NULL, NULL) == 1);

    /* And repeat for x-only. */
    s_overflow[31] += 1;
    CHECK(secp256k1_ecdh_xonly(CTX, output, point_ser + 1, s_zero, NULL, NULL) == 0);
    CHECK(secp256k1_ecdh_xonly(CTX, output, point_ser + 1, s_overflow, NULL, NULL) == 0);
    s_overflow[31] -= 1;
    CHECK(secp256k1_ecdh_xonly(CTX, output, point_ser + 1, s_overflow, NULL, NULL) == 1);

    /* Hash function failure results in ecdh failure */
    CHECK(secp256k1_ecdh(CTX, output, &point, s_overflow, ecdh_hash_function_test_fail, NULL) == 0);
    CHECK(secp256k1_ecdh_xonly(CTX, output, point_ser, s_overflow, ecdh_xonly_hash_function_test_fail, NULL) == 0);
}

/** Test that ECDH(sG, 1/s) == ECDH((1/s)G, s) == ECDH(G, 1) for a few random s. */
static void test_result_basepoint(void) {
    secp256k1_pubkey point;
    secp256k1_scalar rand;
    unsigned char point_ser[33];
    unsigned char x32_g[32];
    unsigned char s[32];
    unsigned char s_inv[32];
    unsigned char out[32];
    unsigned char out_inv[32];
    unsigned char out_base[32];
    unsigned char out_base_xonly[32];
    size_t point_ser_len;
    int i;

    unsigned char s_one[32] = { 0 };
    s_one[31] = 1;
    secp256k1_fe_get_b32(x32_g, &secp256k1_ge_const_g.x);
    CHECK(secp256k1_ec_pubkey_create(CTX, &point, s_one) == 1);
    CHECK(secp256k1_ecdh(CTX, out_base, &point, s_one, NULL, NULL) == 1);
    CHECK(secp256k1_ecdh_xonly(CTX, out_base_xonly, x32_g, s_one, NULL, NULL) == 1);

    for (i = 0; i < 2 * COUNT; i++) {
        testutil_random_scalar_order(&rand);
        secp256k1_scalar_get_b32(s, &rand);
        secp256k1_scalar_inverse_var(&rand, &rand);
        secp256k1_scalar_get_b32(s_inv, &rand);

        CHECK(secp256k1_ec_pubkey_create(CTX, &point, s) == 1);
        point_ser_len = sizeof(point_ser);
        CHECK(secp256k1_ec_pubkey_serialize(CTX, point_ser, &point_ser_len, &point, SECP256K1_EC_COMPRESSED));

        CHECK(secp256k1_ecdh(CTX, out, &point, s_inv, NULL, NULL) == 1);
        CHECK(secp256k1_memcmp_var(out, out_base, 32) == 0);
        CHECK(secp256k1_ecdh_xonly(CTX, out, point_ser + 1, s_inv, NULL, NULL) == 1);
        CHECK(secp256k1_memcmp_var(out, out_base_xonly, 32) == 0);

        CHECK(secp256k1_ec_pubkey_create(CTX, &point, s_inv) == 1);
        CHECK(secp256k1_ecdh(CTX, out_inv, &point, s, NULL, NULL) == 1);
        point_ser_len = sizeof(point_ser);
        CHECK(secp256k1_ec_pubkey_serialize(CTX, point_ser, &point_ser_len, &point, SECP256K1_EC_COMPRESSED));

        CHECK(secp256k1_memcmp_var(out_inv, out_base, 32) == 0);
        CHECK(secp256k1_ecdh_xonly(CTX, out_inv, point_ser + 1, s, NULL, NULL) == 1);
        CHECK(secp256k1_memcmp_var(out_inv, out_base_xonly, 32) == 0);
    }
}

static void test_ecdh_wycheproof(void) {
#include "../../wycheproof/ecdh_secp256k1_test.h"
    int t;
    for (t = 0; t < SECP256K1_ECDH_WYCHEPROOF_NUMBER_TESTVECTORS; t++) {
        int parsed_ok;
        secp256k1_pubkey point;
        const unsigned char *pk;
        const unsigned char *sk;
        const unsigned char *expected_shared_secret;
        unsigned char output_ecdh[65] = { 0 };

        int expected_result;

        memset(&point, 0, sizeof(point));
        pk = &wycheproof_ecdh_public_keys[testvectors[t].pk_offset];
        parsed_ok = secp256k1_ec_pubkey_parse(CTX, &point, pk, testvectors[t].pk_len);

        expected_result = testvectors[t].expected_result;
        CHECK(parsed_ok == expected_result);
        if (!parsed_ok) {
            continue;
        }

        sk = &wycheproof_ecdh_private_keys[testvectors[t].sk_offset];
        CHECK(testvectors[t].sk_len == 32);

        CHECK(secp256k1_ecdh(CTX, output_ecdh, &point, sk, ecdh_hash_function_test_xpassthru, NULL) == 1);
        expected_shared_secret = &wycheproof_ecdh_shared_secrets[testvectors[t].shared_offset];

        CHECK(secp256k1_memcmp_var(output_ecdh, expected_shared_secret, testvectors[t].shared_len) == 0);
    }
}

static void run_ecdh_tests(void) {
    test_ecdh_api();
    test_ecdh_generator_basepoint();
    test_bad_scalar();
    test_result_basepoint();
    test_ecdh_wycheproof();
}

#endif /* SECP256K1_MODULE_ECDH_TESTS_H */
