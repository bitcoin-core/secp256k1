/* Copyright (c) 2023 The Navcoin developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef SECP256K1_MODULE_EXPORT_TESTS_H
#define SECP256K1_MODULE_EXPORT_TESTS_H

#include <stdio.h>

static void test_group_mult(void) {
    secp256k1_gej_alias g;
    secp256k1_gej_alias sum1;
    secp256k1_gej_alias sum2;
    secp256k1_gej_alias prod;
    secp256k1_scalar four;

    secp256k1_export_group_get_base_point(&g);
    secp256k1_export_group_add(
        &sum1,
        &g,
        &g
    );
    secp256k1_export_group_add(
        &sum2,
        &sum1,
        &sum1
    );
    
    secp256k1_export_scalar_set_int(
        &four,
        4
    );
    secp256k1_export_group_ecmult(
        &prod,
        &g,
        &four
    );
     
    CHECK(secp256k1_export_group_eq(
        &sum2,
        &prod
    ));
}

static void test_gej_to_ge(void) {
    secp256k1_gej gj;
    secp256k1_ge g;

    secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);
    gej_to_ge(&g, &gj);

    CHECK(secp256k1_fe_equal(&g.x, &secp256k1_ge_const_g.x));
    CHECK(secp256k1_fe_equal(&g.y, &secp256k1_ge_const_g.y));
}

static void test_group_serialize(void) {
    secp256k1_gej pj;
    secp256k1_ge_storage_alias r;
    size_t i;
    uint64_t exp_x[4] = {
        6481385041966929816,
        188021827762530521,
        6170039885052185351,
        8772561819708210092
    };
    uint64_t exp_y[4] = {
        -7185545363635252040,
        -209500633525038055,
        6747795201694173352,
        5204712524664259685
    };
    secp256k1_gej_set_ge(&pj, &secp256k1_ge_const_g);
    secp256k1_export_group_serialize(&r, ALIAS_GEJ(&pj));

    for(i=0;i<4;++i) {
        CHECK(exp_x[i] == r.x.n[i]);
        CHECK(exp_y[i] == r.y.n[i]);
    }
}

static void test_fe_set_b32_mod(void) {
    /* arbitrary 32-byte value well below p */
    unsigned char in[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
    };
    unsigned char out[32];
    secp256k1_fe r;

    secp256k1_export_fe_set_b32_mod(&r, in);
    secp256k1_export_fe_normalize(&r);
    secp256k1_export_fe_get_b32(out, &r);

    CHECK(memcmp(in, out, 32) == 0);
}

static void test_fe_set_b32_limit(void) {
    /* value < p: should succeed and round-trip */
    unsigned char in[32] = {
        0x01,0x02,0x03,0x04,0x05,0x06,0x07,0x08,
        0x09,0x0a,0x0b,0x0c,0x0d,0x0e,0x0f,0x10,
        0x11,0x12,0x13,0x14,0x15,0x16,0x17,0x18,
        0x19,0x1a,0x1b,0x1c,0x1d,0x1e,0x1f,0x20
    };
    unsigned char out[32];
    secp256k1_fe r;
    int ret;

    ret = secp256k1_export_fe_set_b32_limit(&r, in);
    CHECK(ret == 1);
    secp256k1_export_fe_get_b32(out, &r);
    CHECK(memcmp(in, out, 32) == 0);

    /* value >= p (p = fffffffffffffffffffffffffffffffffffffffffffffffffffffffefffffc2f):
       use all-0xff bytes which exceeds p */
    unsigned char overflow[32];
    memset(overflow, 0xff, 32);
    ret = secp256k1_export_fe_set_b32_limit(&r, overflow);
    CHECK(ret == 0);
}

static void run_export_tests(void) {
    test_gej_to_ge();
    test_group_serialize();
    test_group_mult();
    test_fe_set_b32_mod();
    test_fe_set_b32_limit();
}

#endif /* SECP256K1_MODULE_EXPORT_TESTS_H */
