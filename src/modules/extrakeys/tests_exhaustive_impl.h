/***********************************************************************
 * Copyright (c) 2020 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_EXTRAKEYS_TESTS_EXHAUSTIVE_H
#define SECP256K1_MODULE_EXTRAKEYS_TESTS_EXHAUSTIVE_H

#include "../../../include/secp256k1_extrakeys.h"
#include "main_impl.h"

static void test_exhaustive_extrakeys(const secp256k1_context *ctx, const secp256k1_ge* group) {
    secp256k1_keypair keypair[EXHAUSTIVE_TEST_ORDER - 1];
    secp256k1_pubkey pubkey[EXHAUSTIVE_TEST_ORDER - 1];
    secp256k1_xonly_pubkey xonly_pubkey[EXHAUSTIVE_TEST_ORDER - 1];
    int parities[EXHAUSTIVE_TEST_ORDER - 1];
    unsigned char xonly_pubkey_bytes[EXHAUSTIVE_TEST_ORDER - 1][32];
    int i;

    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {
        secp256k1_fe fe;
        secp256k1_scalar scalar_i;
        unsigned char buf[33];
        int parity;

        secp256k1_scalar_set_int(&scalar_i, i);
        secp256k1_scalar_get_b32(buf, &scalar_i);

        /* Construct pubkey and keypair. */
        CHECK(secp256k1_keypair_create(ctx, &keypair[i - 1], buf));
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey[i - 1], buf));

        /* Construct serialized xonly_pubkey from keypair. */
        CHECK(secp256k1_keypair_xonly_pub(ctx, &xonly_pubkey[i - 1], &parities[i - 1], &keypair[i - 1]));
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, xonly_pubkey_bytes[i - 1], &xonly_pubkey[i - 1]));

        /* Parse the xonly_pubkey back and verify it matches the previously serialized value. */
        CHECK(secp256k1_xonly_pubkey_parse(ctx, &xonly_pubkey[i - 1], xonly_pubkey_bytes[i - 1]));
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, buf, &xonly_pubkey[i - 1]));
        CHECK(secp256k1_memcmp_var(xonly_pubkey_bytes[i - 1], buf, 32) == 0);

        /* Construct the xonly_pubkey from the pubkey, and verify it matches the same. */
        CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &xonly_pubkey[i - 1], &parity, &pubkey[i - 1]));
        CHECK(parity == parities[i - 1]);
        CHECK(secp256k1_xonly_pubkey_serialize(ctx, buf, &xonly_pubkey[i - 1]));
        CHECK(secp256k1_memcmp_var(xonly_pubkey_bytes[i - 1], buf, 32) == 0);

        /* Compare the xonly_pubkey bytes against the precomputed group. */
        secp256k1_fe_set_b32_mod(&fe, xonly_pubkey_bytes[i - 1]);
        CHECK(secp256k1_fe_equal(&fe, &group[i].x));

        /* Check the parity against the precomputed group. */
        fe = group[i].y;
        secp256k1_fe_normalize_var(&fe);
        CHECK(secp256k1_fe_is_odd(&fe) == parities[i - 1]);

        /* Verify that the higher half is identical to the lower half mirrored. */
        if (i > EXHAUSTIVE_TEST_ORDER / 2) {
            CHECK(secp256k1_memcmp_var(xonly_pubkey_bytes[i - 1], xonly_pubkey_bytes[EXHAUSTIVE_TEST_ORDER - i - 1], 32) == 0);
            CHECK(parities[i - 1] == 1 - parities[EXHAUSTIVE_TEST_ORDER - i - 1]);
        }
    }

     /* Check keypair/xonly_pubkey tweak behavior over all non-zero tweaks. */
    for (i = 1; i < EXHAUSTIVE_TEST_ORDER; i++) {
        int j;
        int xonly_scalar = parities[i - 1] ? EXHAUSTIVE_TEST_ORDER - i : i;
        secp256k1_scalar scalar_i;
        unsigned char sk32[32];

        secp256k1_scalar_set_int(&scalar_i, i);
        secp256k1_scalar_get_b32(sk32, &scalar_i);

        for (j = 0; j < EXHAUSTIVE_TEST_ORDER; j++) {
            secp256k1_scalar scalar_j;
            unsigned char tweak32[32];
            int expected_scalar;

            secp256k1_pubkey tweaked_pk;
            secp256k1_xonly_pubkey tweaked_xonly_pk;
            secp256k1_keypair tweaked_keypair;
            unsigned char serialized_pk[33];
            unsigned char serialized_xonly_pk[32];
            unsigned char expected_x[32];
            size_t serialized_pklen = sizeof(serialized_pk);
            int expected_ret;
            int expected_pk_parity;
            int pk_parity;

            secp256k1_scalar_set_int(&scalar_j, j);
            secp256k1_scalar_get_b32(tweak32, &scalar_j);

            expected_scalar = (xonly_scalar + j) % EXHAUSTIVE_TEST_ORDER;
            expected_ret = expected_scalar != 0;

            CHECK(secp256k1_xonly_pubkey_tweak_add(ctx, &tweaked_pk, &xonly_pubkey[i - 1], tweak32) == expected_ret);
            CHECK(secp256k1_keypair_create(ctx, &tweaked_keypair, sk32) == 1);
            CHECK(secp256k1_keypair_xonly_tweak_add(ctx, &tweaked_keypair, tweak32) == expected_ret);

            if (!expected_ret) {
                continue;
            }

            {
                secp256k1_fe y = group[expected_scalar].y;
                secp256k1_fe_normalize_var(&y);
                expected_pk_parity = secp256k1_fe_is_odd(&y);
            }
            {
                secp256k1_fe x = group[expected_scalar].x;
                secp256k1_fe_normalize_var(&x);
                secp256k1_fe_get_b32(expected_x, &x);
            }

            CHECK(secp256k1_ec_pubkey_serialize(ctx, serialized_pk, &serialized_pklen, &tweaked_pk, SECP256K1_EC_COMPRESSED));
            CHECK(serialized_pklen == sizeof(serialized_pk));
            CHECK((serialized_pk[0] == SECP256K1_TAG_PUBKEY_EVEN) || (serialized_pk[0] == SECP256K1_TAG_PUBKEY_ODD));
            CHECK(serialized_pk[0] == (expected_pk_parity ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN));
            CHECK(secp256k1_memcmp_var(&serialized_pk[1], expected_x, 32) == 0);

            CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &tweaked_xonly_pk, &pk_parity, &tweaked_pk));
            CHECK(pk_parity == expected_pk_parity);
            CHECK(secp256k1_xonly_pubkey_serialize(ctx, serialized_xonly_pk, &tweaked_xonly_pk));
            CHECK(secp256k1_memcmp_var(serialized_xonly_pk, expected_x, 32) == 0);
            CHECK(secp256k1_xonly_pubkey_tweak_add_check(ctx, serialized_xonly_pk, pk_parity, &xonly_pubkey[i - 1], tweak32));

            CHECK(secp256k1_keypair_pub(ctx, &tweaked_pk, &tweaked_keypair));
            serialized_pklen = sizeof(serialized_pk);
            CHECK(secp256k1_ec_pubkey_serialize(ctx, serialized_pk, &serialized_pklen, &tweaked_pk, SECP256K1_EC_COMPRESSED));
            CHECK(serialized_pk[0] == (expected_pk_parity ? SECP256K1_TAG_PUBKEY_ODD : SECP256K1_TAG_PUBKEY_EVEN));
            CHECK(secp256k1_memcmp_var(&serialized_pk[1], expected_x, 32) == 0);
        }
    }
}

#endif
