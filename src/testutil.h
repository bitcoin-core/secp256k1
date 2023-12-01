/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_TESTUTIL_H
#define SECP256K1_TESTUTIL_H

#include "field.h"
#include "group.h"
#include "testrand.h"
#include "util.h"

static void random_fe(secp256k1_fe *x) {
    unsigned char bin[32];
    do {
        secp256k1_testrand256(bin);
        if (secp256k1_fe_set_b32_limit(x, bin)) {
            return;
        }
    } while(1);
}

static void random_fe_non_zero(secp256k1_fe *nz) {
    do {
        random_fe(nz);
    } while (secp256k1_fe_is_zero(nz));
}

static void ge_equals_ge(const secp256k1_ge *a, const secp256k1_ge *b) {
    CHECK(secp256k1_ge_eq_var(a, b));
}

static void ge_equals_gej(const secp256k1_ge *a, const secp256k1_gej *b) {
    CHECK(secp256k1_gej_eq_ge_var(b, a));
}

#endif /* SECP256K1_TESTUTIL_H */
