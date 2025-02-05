/* Copyright (c) 2023 The Navcoin developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef SECP256K1_MODULE_EXPORT_TESTS_H
#define SECP256K1_MODULE_EXPORT_TESTS_H

#include <stdio.h>

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

static void run_export_tests(void) {
    test_gej_to_ge();
    test_group_serialize();
}

#endif /* SECP256K1_MODULE_EXPORT_TESTS_H */
