/**********************************************************************
 * Copyright (c) 2020 Jonas Nick                                      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_EXTRAKEYS_TESTS_
#define _SECP256K1_MODULE_EXTRAKEYS_TESTS_

#include "secp256k1_extrakeys.h"

static secp256k1_context* api_test_context(int flags, int *ecount) {
    secp256k1_context *ctx0 = secp256k1_context_create(flags);
    secp256k1_context_set_error_callback(ctx0, counting_illegal_callback_fn, ecount);
    secp256k1_context_set_illegal_callback(ctx0, counting_illegal_callback_fn, ecount);
    return ctx0;
}

void test_xonly_pubkey(void) {
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

    int ecount;
    secp256k1_context *none = api_test_context(SECP256K1_CONTEXT_NONE, &ecount);
    secp256k1_context *sign = api_test_context(SECP256K1_CONTEXT_SIGN, &ecount);
    secp256k1_context *verify = api_test_context(SECP256K1_CONTEXT_VERIFY, &ecount);

    secp256k1_rand256(sk);
    memset(ones32, 0xFF, 32);
    secp256k1_rand256(xy_sk);
    CHECK(secp256k1_ec_pubkey_create(sign, &pk, sk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(none, &xonly_pk, &pk_parity, &pk) == 1);

    /* Test xonly_pubkey_from_pubkey */
    ecount = 0;
    CHECK(secp256k1_xonly_pubkey_from_pubkey(none, &xonly_pk, &pk_parity, &pk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(sign, &xonly_pk, &pk_parity, &pk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(verify, &xonly_pk, &pk_parity, &pk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(none, NULL, &pk_parity, &pk) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(none, &xonly_pk, NULL, &pk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(none, &xonly_pk, &pk_parity, NULL) == 0);
    CHECK(ecount == 2);
    memset(&pk, 0, sizeof(pk));
    CHECK(secp256k1_xonly_pubkey_from_pubkey(none, &xonly_pk, &pk_parity, &pk) == 0);
    CHECK(ecount == 3);

    /* Choose a secret key such that the resulting pubkey and xonly_pubkey match. */
    memset(sk, 0, sizeof(sk));
    sk[0] = 1;
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk, sk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pk, &pk_parity, &pk) == 1);
    CHECK(memcmp(&pk, &xonly_pk, sizeof(pk)) == 0);
    CHECK(pk_parity == 0);

    /* Choose a secret key such that pubkey and xonly_pubkey are each others
     * negation. */
    sk[0] = 2;
    CHECK(secp256k1_ec_pubkey_create(ctx, &pk, sk) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pk, &pk_parity, &pk) == 1);
    CHECK(memcmp(&xonly_pk, &pk, sizeof(xonly_pk)) != 0);
    CHECK(pk_parity == 1);
    secp256k1_pubkey_load(ctx, &pk1, &pk);
    secp256k1_pubkey_load(ctx, &pk2, (secp256k1_pubkey *) &xonly_pk);
    CHECK(secp256k1_fe_equal(&pk1.x, &pk2.x) == 1);
    secp256k1_fe_negate(&y, &pk2.y, 1);
    CHECK(secp256k1_fe_equal(&pk1.y, &y) == 1);

    /* Test xonly_pubkey_serialize and xonly_pubkey_parse */
    ecount = 0;
    CHECK(secp256k1_xonly_pubkey_serialize(none, NULL, &xonly_pk) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_xonly_pubkey_serialize(none, buf32, NULL) == 0);
    CHECK(memcmp(buf32, zeros64, 32) == 0);
    CHECK(ecount == 2);
    {
        /* A pubkey filled with 0s will fail to serialize due to pubkey_load
         * special casing. */
        secp256k1_xonly_pubkey pk_tmp;
        memset(&pk_tmp, 0, sizeof(pk_tmp));
        CHECK(secp256k1_xonly_pubkey_serialize(none, buf32, &pk_tmp) == 0);
    }
    /* pubkey_load called illegal callback */
    CHECK(ecount == 3);

    CHECK(secp256k1_xonly_pubkey_serialize(none, buf32, &xonly_pk) == 1);
    ecount = 0;
    CHECK(secp256k1_xonly_pubkey_parse(none, NULL, buf32) == 0);
    CHECK(ecount == 1);
    CHECK(secp256k1_xonly_pubkey_parse(none, &xonly_pk, NULL) == 0);
    CHECK(ecount == 2);

    /* Serialization and parse roundtrip */
    CHECK(secp256k1_xonly_pubkey_from_pubkey(none, &xonly_pk, NULL, &pk) == 1);
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, buf32, &xonly_pk) == 1);
    CHECK(secp256k1_xonly_pubkey_parse(ctx, &xonly_pk_tmp, buf32) == 1);
    CHECK(memcmp(&xonly_pk, &xonly_pk_tmp, sizeof(xonly_pk)) == 0);

    /* Test parsing invalid field elements */
    memset(&xonly_pk, 1, sizeof(xonly_pk));
    /* Overflowing field element */
    CHECK(secp256k1_xonly_pubkey_parse(none, &xonly_pk, ones32) == 0);
    CHECK(memcmp(&xonly_pk, zeros64, sizeof(xonly_pk)) == 0);
    memset(&xonly_pk, 1, sizeof(xonly_pk));
    /* There's no point with x-coordinate 0 on secp256k1 */
    CHECK(secp256k1_xonly_pubkey_parse(none, &xonly_pk, zeros64) == 0);
    CHECK(memcmp(&xonly_pk, zeros64, sizeof(xonly_pk)) == 0);
    /* If a random 32-byte string can not be parsed with ec_pubkey_parse
     * (because interpreted as X coordinate it does not correspond to a point on
     * the curve) then xonly_pubkey_parse should fail as well. */
    for (i = 0; i < count; i++) {
        unsigned char rand33[33];
        secp256k1_rand256(&rand33[1]);
        rand33[0] = SECP256K1_TAG_PUBKEY_EVEN;
        if (!secp256k1_ec_pubkey_parse(ctx, &pk, rand33, 33)) {
            memset(&xonly_pk, 1, sizeof(xonly_pk));
            CHECK(secp256k1_xonly_pubkey_parse(ctx, &xonly_pk, &rand33[1]) == 0);
            CHECK(memcmp(&xonly_pk, zeros64, sizeof(xonly_pk)) == 0);
        } else {
            CHECK(secp256k1_xonly_pubkey_parse(ctx, &xonly_pk, &rand33[1]) == 1);
        }
    }
    CHECK(ecount == 2);

    secp256k1_context_destroy(none);
    secp256k1_context_destroy(sign);
    secp256k1_context_destroy(verify);
}

void run_extrakeys_tests(void) {
    /* xonly key test cases */
    test_xonly_pubkey();
}

#endif
