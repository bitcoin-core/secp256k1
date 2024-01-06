/***********************************************************************
 * Copyright (c) 2020 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_EXTRAKEYS_TESTS_H
#define SECP256K1_MODULE_EXTRAKEYS_TESTS_H

#include "../../../include/secp256k1_extrakeys.h"

static void test_xonly_pubkey(void) {
    secp256k1_pubkey pk;
    secp256k1_xonly_pubkey xonly_pk, xonly_pk_tmp;
    secp256k1_ge pk1;
    secp256k1_ge pk2;
    secp256k1_fe y;
    unsigned char sk[32];
    unsigned char xy_sk[32];
    unsigned char buf32[32];
    unsigned char ones32[32];
    unsigned char zeros64[64] = { 0 };
    int pk_parity;
    int i;

    secp256k1_testrand256(sk);
    memset(ones32, 0xFF, 32);
    secp256k1_testrand256(xy_sk);
    CHECK(secp256k1_ec_pubkey_create(CTX, &pk, sk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, &pk_parity, &pk) == 1);

    /* Test xonly_pubkey_from_pubkey */
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, &pk_parity, &pk) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_from_pubkey(CTX, NULL, &pk_parity, &pk));
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, NULL, &pk) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, &pk_parity, NULL));
    memset(&pk, 0, sizeof(pk));
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, &pk_parity, &pk));

    /* Choose a secret key such that the resulting pubkey and xonly_pubkey match. */
    memset(sk, 0, sizeof(sk));
    sk[0] = 1;
    CHECK(secp256k1_ec_pubkey_create(CTX, &pk, sk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, &pk_parity, &pk) == 1);
    CHECK(secp256k1_memcmp_var(&pk, &xonly_pk, sizeof(pk)) == 0);
    CHECK(pk_parity == 0);

    /* Choose a secret key such that pubkey and xonly_pubkey are each others
     * negation. */
    sk[0] = 2;
    CHECK(secp256k1_ec_pubkey_create(CTX, &pk, sk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, &pk_parity, &pk) == 1);
    CHECK(secp256k1_memcmp_var(&xonly_pk, &pk, sizeof(xonly_pk)) != 0);
    CHECK(pk_parity == 1);
    secp256k1_pubkey_load(CTX, &pk1, &pk);
    secp256k1_pubkey_load(CTX, &pk2, (secp256k1_pubkey *) &xonly_pk);
    CHECK(secp256k1_fe_equal(&pk1.x, &pk2.x) == 1);
    secp256k1_fe_negate(&y, &pk2.y, 1);
    CHECK(secp256k1_fe_equal(&pk1.y, &y) == 1);

    /* Test xonly_pubkey_serialize and xonly_pubkey_parse */
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_serialize(CTX, NULL, &xonly_pk));
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_serialize(CTX, buf32, NULL));
    CHECK(secp256k1_memcmp_var(buf32, zeros64, 32) == 0);
    {
        /* A pubkey filled with 0s will fail to serialize due to pubkey_load
         * special casing. */
        secp256k1_xonly_pubkey pk_tmp;
        memset(&pk_tmp, 0, sizeof(pk_tmp));
        /* pubkey_load calls illegal callback */
        CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_serialize(CTX, buf32, &pk_tmp));
    }

    CHECK(secp256k1_xonly_pubkey_serialize(CTX, buf32, &xonly_pk) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_parse(CTX, NULL, buf32));
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_parse(CTX, &xonly_pk, NULL));

    /* Serialization and parse roundtrip */
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, NULL, &pk) == 1);
    CHECK(secp256k1_xonly_pubkey_serialize(CTX, buf32, &xonly_pk) == 1);
    CHECK(secp256k1_xonly_pubkey_parse(CTX, &xonly_pk_tmp, buf32) == 1);
    CHECK(secp256k1_memcmp_var(&xonly_pk, &xonly_pk_tmp, sizeof(xonly_pk)) == 0);

    /* Test parsing invalid field elements */
    memset(&xonly_pk, 1, sizeof(xonly_pk));
    /* Overflowing field element */
    CHECK(secp256k1_xonly_pubkey_parse(CTX, &xonly_pk, ones32) == 0);
    CHECK(secp256k1_memcmp_var(&xonly_pk, zeros64, sizeof(xonly_pk)) == 0);
    memset(&xonly_pk, 1, sizeof(xonly_pk));
    /* There's no point with x-coordinate 0 on secp256k1 */
    CHECK(secp256k1_xonly_pubkey_parse(CTX, &xonly_pk, zeros64) == 0);
    CHECK(secp256k1_memcmp_var(&xonly_pk, zeros64, sizeof(xonly_pk)) == 0);
    /* If a random 32-byte string can not be parsed with ec_pubkey_parse
     * (because interpreted as X coordinate it does not correspond to a point on
     * the curve) then xonly_pubkey_parse should fail as well. */
    for (i = 0; i < COUNT; i++) {
        unsigned char rand33[33];
        secp256k1_testrand256(&rand33[1]);
        rand33[0] = SECP256K1_TAG_PUBKEY_EVEN;
        if (!secp256k1_ec_pubkey_parse(CTX, &pk, rand33, 33)) {
            memset(&xonly_pk, 1, sizeof(xonly_pk));
            CHECK(secp256k1_xonly_pubkey_parse(CTX, &xonly_pk, &rand33[1]) == 0);
            CHECK(secp256k1_memcmp_var(&xonly_pk, zeros64, sizeof(xonly_pk)) == 0);
        } else {
            CHECK(secp256k1_xonly_pubkey_parse(CTX, &xonly_pk, &rand33[1]) == 1);
        }
    }
}

static void test_xonly_pubkey_comparison(void) {
    unsigned char pk1_ser[32] = {
        0x58, 0x84, 0xb3, 0xa2, 0x4b, 0x97, 0x37, 0x88, 0x92, 0x38, 0xa6, 0x26, 0x62, 0x52, 0x35, 0x11,
        0xd0, 0x9a, 0xa1, 0x1b, 0x80, 0x0b, 0x5e, 0x93, 0x80, 0x26, 0x11, 0xef, 0x67, 0x4b, 0xd9, 0x23
    };
    const unsigned char pk2_ser[32] = {
        0xde, 0x36, 0x0e, 0x87, 0x59, 0x8f, 0x3c, 0x01, 0x36, 0x2a, 0x2a, 0xb8, 0xc6, 0xf4, 0x5e, 0x4d,
        0xb2, 0xc2, 0xd5, 0x03, 0xa7, 0xf9, 0xf1, 0x4f, 0xa8, 0xfa, 0x95, 0xa8, 0xe9, 0x69, 0x76, 0x1c
    };
    secp256k1_xonly_pubkey pk1;
    secp256k1_xonly_pubkey pk2;

    CHECK(secp256k1_xonly_pubkey_parse(CTX, &pk1, pk1_ser) == 1);
    CHECK(secp256k1_xonly_pubkey_parse(CTX, &pk2, pk2_ser) == 1);

    CHECK_ILLEGAL_VOID(CTX, CHECK(secp256k1_xonly_pubkey_cmp(CTX, NULL, &pk2) < 0));
    CHECK_ILLEGAL_VOID(CTX, CHECK(secp256k1_xonly_pubkey_cmp(CTX, &pk1, NULL) > 0));
    CHECK(secp256k1_xonly_pubkey_cmp(CTX, &pk1, &pk2) < 0);
    CHECK(secp256k1_xonly_pubkey_cmp(CTX, &pk2, &pk1) > 0);
    CHECK(secp256k1_xonly_pubkey_cmp(CTX, &pk1, &pk1) == 0);
    CHECK(secp256k1_xonly_pubkey_cmp(CTX, &pk2, &pk2) == 0);
    memset(&pk1, 0, sizeof(pk1)); /* illegal pubkey */
    CHECK_ILLEGAL_VOID(CTX, CHECK(secp256k1_xonly_pubkey_cmp(CTX, &pk1, &pk2) < 0));
    {
        int32_t ecount = 0;
        secp256k1_context_set_illegal_callback(CTX, counting_callback_fn, &ecount);
        CHECK(secp256k1_xonly_pubkey_cmp(CTX, &pk1, &pk1) == 0);
        CHECK(ecount == 2);
        secp256k1_context_set_illegal_callback(CTX, NULL, NULL);
    }
    CHECK_ILLEGAL_VOID(CTX, CHECK(secp256k1_xonly_pubkey_cmp(CTX, &pk2, &pk1) > 0));
}

static void test_xonly_pubkey_tweak(void) {
    unsigned char zeros64[64] = { 0 };
    unsigned char overflows[32];
    unsigned char sk[32];
    secp256k1_pubkey internal_pk;
    secp256k1_xonly_pubkey internal_xonly_pk;
    secp256k1_pubkey output_pk;
    int pk_parity;
    unsigned char tweak[32];
    int i;

    memset(overflows, 0xff, sizeof(overflows));
    secp256k1_testrand256(tweak);
    secp256k1_testrand256(sk);
    CHECK(secp256k1_ec_pubkey_create(CTX, &internal_pk, sk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &internal_xonly_pk, &pk_parity, &internal_pk) == 1);

    CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, tweak) == 1);
    CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, tweak) == 1);
    CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, tweak) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_tweak_add(CTX, NULL, &internal_xonly_pk, tweak));
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, NULL, tweak));
    /* NULL internal_xonly_pk zeroes the output_pk */
    CHECK(secp256k1_memcmp_var(&output_pk, zeros64, sizeof(output_pk)) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, NULL));
    /* NULL tweak zeroes the output_pk */
    CHECK(secp256k1_memcmp_var(&output_pk, zeros64, sizeof(output_pk)) == 0);

    /* Invalid tweak zeroes the output_pk */
    CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, overflows) == 0);
    CHECK(secp256k1_memcmp_var(&output_pk, zeros64, sizeof(output_pk))  == 0);

    /* A zero tweak is fine */
    CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, zeros64) == 1);

    /* Fails if the resulting key was infinity */
    for (i = 0; i < COUNT; i++) {
        secp256k1_scalar scalar_tweak;
        /* Because sk may be negated before adding, we need to try with tweak =
         * sk as well as tweak = -sk. */
        secp256k1_scalar_set_b32(&scalar_tweak, sk, NULL);
        secp256k1_scalar_negate(&scalar_tweak, &scalar_tweak);
        secp256k1_scalar_get_b32(tweak, &scalar_tweak);
        CHECK((secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, sk) == 0)
              || (secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, tweak) == 0));
        CHECK(secp256k1_memcmp_var(&output_pk, zeros64, sizeof(output_pk)) == 0);
    }

    /* Invalid pk with a valid tweak */
    memset(&internal_xonly_pk, 0, sizeof(internal_xonly_pk));
    secp256k1_testrand256(tweak);
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, tweak));
    CHECK(secp256k1_memcmp_var(&output_pk, zeros64, sizeof(output_pk))  == 0);
}

static void test_xonly_pubkey_tweak_check(void) {
    unsigned char zeros64[64] = { 0 };
    unsigned char overflows[32];
    unsigned char sk[32];
    secp256k1_pubkey internal_pk;
    secp256k1_xonly_pubkey internal_xonly_pk;
    secp256k1_pubkey output_pk;
    secp256k1_xonly_pubkey output_xonly_pk;
    unsigned char output_pk32[32];
    unsigned char buf32[32];
    int pk_parity;
    unsigned char tweak[32];

    memset(overflows, 0xff, sizeof(overflows));
    secp256k1_testrand256(tweak);
    secp256k1_testrand256(sk);
    CHECK(secp256k1_ec_pubkey_create(CTX, &internal_pk, sk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &internal_xonly_pk, &pk_parity, &internal_pk) == 1);

    CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, tweak) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &output_xonly_pk, &pk_parity, &output_pk) == 1);
    CHECK(secp256k1_xonly_pubkey_serialize(CTX, buf32, &output_xonly_pk) == 1);
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, buf32, pk_parity, &internal_xonly_pk, tweak) == 1);
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, buf32, pk_parity, &internal_xonly_pk, tweak) == 1);
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, buf32, pk_parity, &internal_xonly_pk, tweak) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_tweak_add_check(CTX, NULL, pk_parity, &internal_xonly_pk, tweak));
    /* invalid pk_parity value */
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, buf32, 2, &internal_xonly_pk, tweak) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_tweak_add_check(CTX, buf32, pk_parity, NULL, tweak));
    CHECK_ILLEGAL(CTX, secp256k1_xonly_pubkey_tweak_add_check(CTX, buf32, pk_parity, &internal_xonly_pk, NULL));

    memset(tweak, 1, sizeof(tweak));
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &internal_xonly_pk, NULL, &internal_pk) == 1);
    CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, tweak) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &output_xonly_pk, &pk_parity, &output_pk) == 1);
    CHECK(secp256k1_xonly_pubkey_serialize(CTX, output_pk32, &output_xonly_pk) == 1);
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, output_pk32, pk_parity, &internal_xonly_pk, tweak) == 1);

    /* Wrong pk_parity */
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, output_pk32, !pk_parity, &internal_xonly_pk, tweak) == 0);
    /* Wrong public key */
    CHECK(secp256k1_xonly_pubkey_serialize(CTX, buf32, &internal_xonly_pk) == 1);
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, buf32, pk_parity, &internal_xonly_pk, tweak) == 0);

    /* Overflowing tweak not allowed */
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, output_pk32, pk_parity, &internal_xonly_pk, overflows) == 0);
    CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk, &internal_xonly_pk, overflows) == 0);
    CHECK(secp256k1_memcmp_var(&output_pk, zeros64, sizeof(output_pk)) == 0);
}

/* Starts with an initial pubkey and recursively creates N_PUBKEYS - 1
 * additional pubkeys by calling tweak_add. Then verifies every tweak starting
 * from the last pubkey. */
#define N_PUBKEYS 32
static void test_xonly_pubkey_tweak_recursive(void) {
    unsigned char sk[32];
    secp256k1_pubkey pk[N_PUBKEYS];
    unsigned char pk_serialized[32];
    unsigned char tweak[N_PUBKEYS - 1][32];
    int i;

    secp256k1_testrand256(sk);
    CHECK(secp256k1_ec_pubkey_create(CTX, &pk[0], sk) == 1);
    /* Add tweaks */
    for (i = 0; i < N_PUBKEYS - 1; i++) {
        secp256k1_xonly_pubkey xonly_pk;
        memset(tweak[i], i + 1, sizeof(tweak[i]));
        CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, NULL, &pk[i]) == 1);
        CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &pk[i + 1], &xonly_pk, tweak[i]) == 1);
    }

    /* Verify tweaks */
    for (i = N_PUBKEYS - 1; i > 0; i--) {
        secp256k1_xonly_pubkey xonly_pk;
        int pk_parity;
        CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, &pk_parity, &pk[i]) == 1);
        CHECK(secp256k1_xonly_pubkey_serialize(CTX, pk_serialized, &xonly_pk) == 1);
        CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, NULL, &pk[i - 1]) == 1);
        CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, pk_serialized, pk_parity, &xonly_pk, tweak[i - 1]) == 1);
    }
}
#undef N_PUBKEYS

static void test_keypair(void) {
    unsigned char sk[32];
    unsigned char sk_tmp[32];
    unsigned char zeros96[96] = { 0 };
    unsigned char overflows[32];
    secp256k1_keypair keypair;
    secp256k1_pubkey pk, pk_tmp;
    secp256k1_xonly_pubkey xonly_pk, xonly_pk_tmp;
    int pk_parity, pk_parity_tmp;

    CHECK(sizeof(zeros96) == sizeof(keypair));
    memset(overflows, 0xFF, sizeof(overflows));

    /* Test keypair_create */
    secp256k1_testrand256(sk);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_memcmp_var(zeros96, &keypair, sizeof(keypair)) != 0);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_memcmp_var(zeros96, &keypair, sizeof(keypair)) != 0);
    CHECK_ILLEGAL(CTX, secp256k1_keypair_create(CTX, NULL, sk));
    CHECK_ILLEGAL(CTX, secp256k1_keypair_create(CTX, &keypair, NULL));
    CHECK(secp256k1_memcmp_var(zeros96, &keypair, sizeof(keypair)) == 0);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_keypair_create(STATIC_CTX, &keypair, sk));
    CHECK(secp256k1_memcmp_var(zeros96, &keypair, sizeof(keypair)) == 0);

    /* Invalid secret key */
    CHECK(secp256k1_keypair_create(CTX, &keypair, zeros96) == 0);
    CHECK(secp256k1_memcmp_var(zeros96, &keypair, sizeof(keypair)) == 0);
    CHECK(secp256k1_keypair_create(CTX, &keypair, overflows) == 0);
    CHECK(secp256k1_memcmp_var(zeros96, &keypair, sizeof(keypair)) == 0);

    /* Test keypair_pub */
    secp256k1_testrand256(sk);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_pub(CTX, &pk, &keypair) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_keypair_pub(CTX, NULL, &keypair));
    CHECK_ILLEGAL(CTX, secp256k1_keypair_pub(CTX, &pk, NULL));
    CHECK(secp256k1_memcmp_var(zeros96, &pk, sizeof(pk)) == 0);

    /* Using an invalid keypair is fine for keypair_pub */
    memset(&keypair, 0, sizeof(keypair));
    CHECK(secp256k1_keypair_pub(CTX, &pk, &keypair) == 1);
    CHECK(secp256k1_memcmp_var(zeros96, &pk, sizeof(pk)) == 0);

    /* keypair holds the same pubkey as pubkey_create */
    CHECK(secp256k1_ec_pubkey_create(CTX, &pk, sk) == 1);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_pub(CTX, &pk_tmp, &keypair) == 1);
    CHECK(secp256k1_memcmp_var(&pk, &pk_tmp, sizeof(pk)) == 0);

    /** Test keypair_xonly_pub **/
    secp256k1_testrand256(sk);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_pub(CTX, &xonly_pk, &pk_parity, &keypair) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_keypair_xonly_pub(CTX, NULL, &pk_parity, &keypair));
    CHECK(secp256k1_keypair_xonly_pub(CTX, &xonly_pk, NULL, &keypair) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_keypair_xonly_pub(CTX, &xonly_pk, &pk_parity, NULL));
    CHECK(secp256k1_memcmp_var(zeros96, &xonly_pk, sizeof(xonly_pk)) == 0);
    /* Using an invalid keypair will set the xonly_pk to 0 (first reset
     * xonly_pk). */
    CHECK(secp256k1_keypair_xonly_pub(CTX, &xonly_pk, &pk_parity, &keypair) == 1);
    memset(&keypair, 0, sizeof(keypair));
    CHECK_ILLEGAL(CTX, secp256k1_keypair_xonly_pub(CTX, &xonly_pk, &pk_parity, &keypair));
    CHECK(secp256k1_memcmp_var(zeros96, &xonly_pk, sizeof(xonly_pk)) == 0);

    /** keypair holds the same xonly pubkey as pubkey_create **/
    CHECK(secp256k1_ec_pubkey_create(CTX, &pk, sk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(CTX, &xonly_pk, &pk_parity, &pk) == 1);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_pub(CTX, &xonly_pk_tmp, &pk_parity_tmp, &keypair) == 1);
    CHECK(secp256k1_memcmp_var(&xonly_pk, &xonly_pk_tmp, sizeof(pk)) == 0);
    CHECK(pk_parity == pk_parity_tmp);

    /* Test keypair_seckey */
    secp256k1_testrand256(sk);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_sec(CTX, sk_tmp, &keypair) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_keypair_sec(CTX, NULL, &keypair));
    CHECK_ILLEGAL(CTX, secp256k1_keypair_sec(CTX, sk_tmp, NULL));
    CHECK(secp256k1_memcmp_var(zeros96, sk_tmp, sizeof(sk_tmp)) == 0);

    /* keypair returns the same seckey it got */
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_sec(CTX, sk_tmp, &keypair) == 1);
    CHECK(secp256k1_memcmp_var(sk, sk_tmp, sizeof(sk_tmp)) == 0);


    /* Using an invalid keypair is fine for keypair_seckey */
    memset(&keypair, 0, sizeof(keypair));
    CHECK(secp256k1_keypair_sec(CTX, sk_tmp, &keypair) == 1);
    CHECK(secp256k1_memcmp_var(zeros96, sk_tmp, sizeof(sk_tmp)) == 0);
}

static void test_keypair_add(void) {
    unsigned char sk[32];
    secp256k1_keypair keypair;
    unsigned char overflows[32];
    unsigned char zeros96[96] = { 0 };
    unsigned char tweak[32];
    int i;

    CHECK(sizeof(zeros96) == sizeof(keypair));
    secp256k1_testrand256(sk);
    secp256k1_testrand256(tweak);
    memset(overflows, 0xFF, 32);
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);

    CHECK(secp256k1_keypair_xonly_tweak_add(CTX, &keypair, tweak) == 1);
    CHECK(secp256k1_keypair_xonly_tweak_add(CTX, &keypair, tweak) == 1);
    CHECK(secp256k1_keypair_xonly_tweak_add(CTX, &keypair, tweak) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_keypair_xonly_tweak_add(CTX, NULL, tweak));
    CHECK_ILLEGAL(CTX, secp256k1_keypair_xonly_tweak_add(CTX, &keypair, NULL));
    /* This does not set the keypair to zeroes */
    CHECK(secp256k1_memcmp_var(&keypair, zeros96, sizeof(keypair)) != 0);

    /* Invalid tweak zeroes the keypair */
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_tweak_add(CTX, &keypair, overflows) == 0);
    CHECK(secp256k1_memcmp_var(&keypair, zeros96, sizeof(keypair))  == 0);

    /* A zero tweak is fine */
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    CHECK(secp256k1_keypair_xonly_tweak_add(CTX, &keypair, zeros96) == 1);

    /* Fails if the resulting keypair was (sk=0, pk=infinity) */
    for (i = 0; i < COUNT; i++) {
        secp256k1_scalar scalar_tweak;
        secp256k1_keypair keypair_tmp;
        secp256k1_testrand256(sk);
        CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
        memcpy(&keypair_tmp, &keypair, sizeof(keypair));
        /* Because sk may be negated before adding, we need to try with tweak =
         * sk as well as tweak = -sk. */
        secp256k1_scalar_set_b32(&scalar_tweak, sk, NULL);
        secp256k1_scalar_negate(&scalar_tweak, &scalar_tweak);
        secp256k1_scalar_get_b32(tweak, &scalar_tweak);
        CHECK((secp256k1_keypair_xonly_tweak_add(CTX, &keypair, sk) == 0)
              || (secp256k1_keypair_xonly_tweak_add(CTX, &keypair_tmp, tweak) == 0));
        CHECK(secp256k1_memcmp_var(&keypair, zeros96, sizeof(keypair)) == 0
              || secp256k1_memcmp_var(&keypair_tmp, zeros96, sizeof(keypair_tmp)) == 0);
    }

    /* Invalid keypair with a valid tweak */
    memset(&keypair, 0, sizeof(keypair));
    secp256k1_testrand256(tweak);
    CHECK_ILLEGAL(CTX, secp256k1_keypair_xonly_tweak_add(CTX, &keypair, tweak));
    CHECK(secp256k1_memcmp_var(&keypair, zeros96, sizeof(keypair))  == 0);
    /* Only seckey part of keypair invalid */
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    memset(&keypair, 0, 32);
    CHECK_ILLEGAL(CTX, secp256k1_keypair_xonly_tweak_add(CTX, &keypair, tweak));
    /* Only pubkey part of keypair invalid */
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    memset(&keypair.data[32], 0, 64);
    CHECK_ILLEGAL(CTX, secp256k1_keypair_xonly_tweak_add(CTX, &keypair, tweak));

    /* Check that the keypair_tweak_add implementation is correct */
    CHECK(secp256k1_keypair_create(CTX, &keypair, sk) == 1);
    for (i = 0; i < COUNT; i++) {
        secp256k1_xonly_pubkey internal_pk;
        secp256k1_xonly_pubkey output_pk;
        secp256k1_pubkey output_pk_xy;
        secp256k1_pubkey output_pk_expected;
        unsigned char pk32[32];
        unsigned char sk32[32];
        int pk_parity;

        secp256k1_testrand256(tweak);
        CHECK(secp256k1_keypair_xonly_pub(CTX, &internal_pk, NULL, &keypair) == 1);
        CHECK(secp256k1_keypair_xonly_tweak_add(CTX, &keypair, tweak) == 1);
        CHECK(secp256k1_keypair_xonly_pub(CTX, &output_pk, &pk_parity, &keypair) == 1);

        /* Check that it passes xonly_pubkey_tweak_add_check */
        CHECK(secp256k1_xonly_pubkey_serialize(CTX, pk32, &output_pk) == 1);
        CHECK(secp256k1_xonly_pubkey_tweak_add_check(CTX, pk32, pk_parity, &internal_pk, tweak) == 1);

        /* Check that the resulting pubkey matches xonly_pubkey_tweak_add */
        CHECK(secp256k1_keypair_pub(CTX, &output_pk_xy, &keypair) == 1);
        CHECK(secp256k1_xonly_pubkey_tweak_add(CTX, &output_pk_expected, &internal_pk, tweak) == 1);
        CHECK(secp256k1_memcmp_var(&output_pk_xy, &output_pk_expected, sizeof(output_pk_xy)) == 0);

        /* Check that the secret key in the keypair is tweaked correctly */
        CHECK(secp256k1_keypair_sec(CTX, sk32, &keypair) == 1);
        CHECK(secp256k1_ec_pubkey_create(CTX, &output_pk_expected, sk32) == 1);
        CHECK(secp256k1_memcmp_var(&output_pk_xy, &output_pk_expected, sizeof(output_pk_xy)) == 0);
    }
}

static void test_hsort_is_sorted(int *ints, size_t n) {
    size_t i;
    for (i = 1; i < n; i++) {
        CHECK(ints[i-1] <= ints[i]);
    }
}

static int test_hsort_cmp(const void *i1, const void *i2, void *counter) {
  *(size_t*)counter += 1;
  return *(int*)i1 - *(int*)i2;
}

#define NUM 64
static void test_hsort(void) {
    int ints[NUM] = { 0 };
    size_t counter = 0;
    int i, j;

    secp256k1_hsort(ints, 0, sizeof(ints[0]), test_hsort_cmp, &counter);
    CHECK(counter == 0);
    secp256k1_hsort(ints, 1, sizeof(ints[0]), test_hsort_cmp, &counter);
    CHECK(counter == 0);
    secp256k1_hsort(ints, NUM, sizeof(ints[0]), test_hsort_cmp, &counter);
    CHECK(counter > 0);
    test_hsort_is_sorted(ints, NUM);

    /* Test hsort with length n array and random elements in
     * [-interval/2, interval/2] */
    for (i = 0; i < COUNT; i++) {
        int n = secp256k1_testrand_int(NUM);
        int interval = secp256k1_testrand_int(63) + 1;
        for (j = 0; j < n; j++) {
            ints[j] = secp256k1_testrand_int(interval) - interval/2;
        }
        secp256k1_hsort(ints, n, sizeof(ints[0]), test_hsort_cmp, &counter);
        test_hsort_is_sorted(ints, n);
    }
}
#undef NUM

static void test_sort_helper(secp256k1_pubkey *pk, size_t *pk_order, size_t n_pk) {
    size_t i;
    const secp256k1_pubkey *pk_test[5];

    for (i = 0; i < n_pk; i++) {
        pk_test[i] = &pk[pk_order[i]];
    }
    secp256k1_pubkey_sort(CTX, pk_test, n_pk);
    for (i = 0; i < n_pk; i++) {
        CHECK(secp256k1_memcmp_var(pk_test[i], &pk[i], sizeof(*pk_test[i])) == 0);
    }
}

static void permute(size_t *arr, size_t n) {
    size_t i;
    for (i = n - 1; i >= 1; i--) {
        size_t tmp, j;
        j = secp256k1_testrand_int(i + 1);
        tmp = arr[i];
        arr[i] = arr[j];
        arr[j] = tmp;
    }
}

static void rand_pk(secp256k1_pubkey *pk) {
    unsigned char seckey[32];
    secp256k1_keypair keypair;
    secp256k1_testrand256(seckey);
    CHECK(secp256k1_keypair_create(CTX, &keypair, seckey) == 1);
    CHECK(secp256k1_keypair_pub(CTX, pk, &keypair) == 1);
}

static void test_sort_api(void) {
    secp256k1_pubkey pks[2];
    const secp256k1_pubkey *pks_ptr[2];

    pks_ptr[0] = &pks[0];
    pks_ptr[1] = &pks[1];

    rand_pk(&pks[0]);
    rand_pk(&pks[1]);

    CHECK(secp256k1_pubkey_sort(CTX, pks_ptr, 2) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_pubkey_sort(CTX, NULL, 2));
    CHECK(secp256k1_pubkey_sort(CTX, pks_ptr, 0) == 1);
    /* Test illegal public keys */
    memset(&pks[0], 0, sizeof(pks[0]));
    CHECK_ILLEGAL_VOID(CTX, CHECK(secp256k1_pubkey_sort(CTX, pks_ptr, 2) == 1));
    memset(&pks[1], 0, sizeof(pks[1]));
    {
        int32_t ecount = 0;
        secp256k1_context_set_illegal_callback(CTX, counting_callback_fn, &ecount);
        CHECK(secp256k1_pubkey_sort(CTX, pks_ptr, 2) == 1);
        CHECK(ecount == 2);
        secp256k1_context_set_illegal_callback(CTX, NULL, NULL);
    }
}

static void test_sort(void) {
    secp256k1_pubkey pk[5];
    unsigned char pk_ser[5][33] = {
        { 0x02, 0x08 },
        { 0x02, 0x0b },
        { 0x02, 0x0c },
        { 0x03, 0x05 },
        { 0x03, 0x0a },
    };
    int i;
    size_t pk_order[5] = { 0, 1, 2, 3, 4 };

    for (i = 0; i < 5; i++) {
        CHECK(secp256k1_ec_pubkey_parse(CTX, &pk[i], pk_ser[i], sizeof(pk_ser[i])));
    }

    permute(pk_order, 1);
    test_sort_helper(pk, pk_order, 1);
    permute(pk_order, 2);
    test_sort_helper(pk, pk_order, 2);
    permute(pk_order, 3);
    test_sort_helper(pk, pk_order, 3);
    for (i = 0; i < COUNT; i++) {
        permute(pk_order, 4);
        test_sort_helper(pk, pk_order, 4);
    }
    for (i = 0; i < COUNT; i++) {
        permute(pk_order, 5);
        test_sort_helper(pk, pk_order, 5);
    }
    /* Check that sorting also works for random pubkeys */
    for (i = 0; i < COUNT; i++) {
        int j;
        const secp256k1_pubkey *pk_ptr[5];
        for (j = 0; j < 5; j++) {
            rand_pk(&pk[j]);
            pk_ptr[j] = &pk[j];
        }
        secp256k1_pubkey_sort(CTX, pk_ptr, 5);
        for (j = 1; j < 5; j++) {
            CHECK(secp256k1_pubkey_sort_cmp(&pk_ptr[j - 1], &pk_ptr[j], CTX) <= 0);
        }
    }
}

/* Test vectors from BIP-MuSig2 */
static void test_sort_vectors(void) {
    enum { N_PUBKEYS = 6 };
    unsigned char pk_ser[N_PUBKEYS][33] = {
        { 0x02, 0xDD, 0x30, 0x8A, 0xFE, 0xC5, 0x77, 0x7E, 0x13, 0x12, 0x1F,
          0xA7, 0x2B, 0x9C, 0xC1, 0xB7, 0xCC, 0x01, 0x39, 0x71, 0x53, 0x09,
          0xB0, 0x86, 0xC9, 0x60, 0xE1, 0x8F, 0xD9, 0x69, 0x77, 0x4E, 0xB8 },
        { 0x02, 0xF9, 0x30, 0x8A, 0x01, 0x92, 0x58, 0xC3, 0x10, 0x49, 0x34,
          0x4F, 0x85, 0xF8, 0x9D, 0x52, 0x29, 0xB5, 0x31, 0xC8, 0x45, 0x83,
          0x6F, 0x99, 0xB0, 0x86, 0x01, 0xF1, 0x13, 0xBC, 0xE0, 0x36, 0xF9 },
        { 0x03, 0xDF, 0xF1, 0xD7, 0x7F, 0x2A, 0x67, 0x1C, 0x5F, 0x36, 0x18,
          0x37, 0x26, 0xDB, 0x23, 0x41, 0xBE, 0x58, 0xFE, 0xAE, 0x1D, 0xA2,
          0xDE, 0xCE, 0xD8, 0x43, 0x24, 0x0F, 0x7B, 0x50, 0x2B, 0xA6, 0x59 },
        { 0x02, 0x35, 0x90, 0xA9, 0x4E, 0x76, 0x8F, 0x8E, 0x18, 0x15, 0xC2,
          0xF2, 0x4B, 0x4D, 0x80, 0xA8, 0xE3, 0x14, 0x93, 0x16, 0xC3, 0x51,
          0x8C, 0xE7, 0xB7, 0xAD, 0x33, 0x83, 0x68, 0xD0, 0x38, 0xCA, 0x66 },
        { 0x02, 0xDD, 0x30, 0x8A, 0xFE, 0xC5, 0x77, 0x7E, 0x13, 0x12, 0x1F,
          0xA7, 0x2B, 0x9C, 0xC1, 0xB7, 0xCC, 0x01, 0x39, 0x71, 0x53, 0x09,
          0xB0, 0x86, 0xC9, 0x60, 0xE1, 0x8F, 0xD9, 0x69, 0x77, 0x4E, 0xFF },
        { 0x02, 0xDD, 0x30, 0x8A, 0xFE, 0xC5, 0x77, 0x7E, 0x13, 0x12, 0x1F,
          0xA7, 0x2B, 0x9C, 0xC1, 0xB7, 0xCC, 0x01, 0x39, 0x71, 0x53, 0x09,
          0xB0, 0x86, 0xC9, 0x60, 0xE1, 0x8F, 0xD9, 0x69, 0x77, 0x4E, 0xB8 }
    };
    secp256k1_pubkey pubkeys[N_PUBKEYS];
    secp256k1_pubkey *sorted[N_PUBKEYS];
    const secp256k1_pubkey *pks_ptr[N_PUBKEYS];
    int i;

    sorted[0] = &pubkeys[3];
    sorted[1] = &pubkeys[0];
    sorted[2] = &pubkeys[0];
    sorted[3] = &pubkeys[4];
    sorted[4] = &pubkeys[1];
    sorted[5] = &pubkeys[2];

    for (i = 0; i < N_PUBKEYS; i++) {
        CHECK(secp256k1_ec_pubkey_parse(CTX, &pubkeys[i], pk_ser[i], sizeof(pk_ser[i])));
        pks_ptr[i] = &pubkeys[i];
    }
    CHECK(secp256k1_pubkey_sort(CTX, pks_ptr, N_PUBKEYS) == 1);
    for (i = 0; i < N_PUBKEYS; i++) {
        CHECK(secp256k1_memcmp_var(pks_ptr[i], sorted[i], sizeof(secp256k1_pubkey)) == 0);
    }
}

static void run_extrakeys_tests(void) {
    /* xonly key test cases */
    test_xonly_pubkey();
    test_xonly_pubkey_tweak();
    test_xonly_pubkey_tweak_check();
    test_xonly_pubkey_tweak_recursive();
    test_xonly_pubkey_comparison();

    /* keypair tests */
    test_keypair();
    test_keypair_add();

    /* sorting tests */
    test_hsort();
    test_sort_api();
    test_sort();
    test_sort_vectors();
}

#endif
