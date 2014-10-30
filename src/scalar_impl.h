// Copyright (c) 2014 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SECP256K1_SCALAR_IMPL_H_
#define _SECP256K1_SCALAR_IMPL_H_

#include <string.h>

#include "scalar.h"

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#if defined(USE_SCALAR_4X64)
#include "scalar_4x64_impl.h"
#elif defined(USE_SCALAR_8X32)
#include "scalar_8x32_impl.h"
#else
#error "Please select scalar implementation"
#endif

void static secp256k1_scalar_get_num(secp256k1_num_t *r, const secp256k1_scalar_t *a) {
    unsigned char c[32];
    secp256k1_scalar_get_b32(c, a);
    secp256k1_num_set_bin(r, c, 32);
}


void static secp256k1_scalar_inverse(secp256k1_scalar_t *r, const secp256k1_scalar_t *x) {
    secp256k1_scalar_mont_t x1;
    secp256k1_scalar_to_mont(&x1, x);

    // First compute x ^ (2^N - 1) for some values of N.
    secp256k1_scalar_mont_t x2, x3, x4, x6, x7, x8, x15, x30, x60, x120, x127;

    secp256k1_scalar_sqr_mont(&x2, &x1);
    secp256k1_scalar_mul_mont(&x2, &x2, &x1);

    secp256k1_scalar_sqr_mont(&x3, &x2);
    secp256k1_scalar_mul_mont(&x3, &x3, &x1);

    secp256k1_scalar_sqr_mont(&x4, &x3);
    secp256k1_scalar_mul_mont(&x4, &x4, &x1);

    secp256k1_scalar_sqr_mont(&x6, &x4);
    secp256k1_scalar_sqr_mont(&x6, &x6);
    secp256k1_scalar_mul_mont(&x6, &x6, &x2);

    secp256k1_scalar_sqr_mont(&x7, &x6);
    secp256k1_scalar_mul_mont(&x7, &x7, &x1);

    secp256k1_scalar_sqr_mont(&x8, &x7);
    secp256k1_scalar_mul_mont(&x8, &x8, &x1);

    secp256k1_scalar_sqr_mont(&x15, &x8);
    for (int i=0; i<6; i++)
        secp256k1_scalar_sqr_mont(&x15, &x15);
    secp256k1_scalar_mul_mont(&x15, &x15, &x7);

    secp256k1_scalar_sqr_mont(&x30, &x15);
    for (int i=0; i<14; i++)
        secp256k1_scalar_sqr_mont(&x30, &x30);
    secp256k1_scalar_mul_mont(&x30, &x30, &x15);

    secp256k1_scalar_sqr_mont(&x60, &x30);
    for (int i=0; i<29; i++)
        secp256k1_scalar_sqr_mont(&x60, &x60);
    secp256k1_scalar_mul_mont(&x60, &x60, &x30);

    secp256k1_scalar_sqr_mont(&x120, &x60);
    for (int i=0; i<59; i++)
        secp256k1_scalar_sqr_mont(&x120, &x120);
    secp256k1_scalar_mul_mont(&x120, &x120, &x60);

    secp256k1_scalar_sqr_mont(&x127, &x120);
    for (int i=0; i<6; i++)
        secp256k1_scalar_sqr_mont(&x127, &x127);
    secp256k1_scalar_mul_mont(&x127, &x127, &x7);

    // Then accumul_montate the final result (t starts at x127).
    secp256k1_scalar_mont_t *t = &x127;
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<4; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x3); // 111
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<4; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x3); // 111
    for (int i=0; i<3; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x2); // 11
    for (int i=0; i<4; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x3); // 111
    for (int i=0; i<5; i++) // 00
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x3); // 111
    for (int i=0; i<4; i++) // 00
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x2); // 11
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<5; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x4); // 1111
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<3; i++) // 00
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<4; i++) // 000
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<10; i++) // 0000000
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x3); // 111
    for (int i=0; i<4; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x3); // 111
    for (int i=0; i<9; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x8); // 11111111
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<3; i++) // 00
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<3; i++) // 00
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<5; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x4); // 1111
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<5; i++) // 000
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x2); // 11
    for (int i=0; i<4; i++) // 00
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x2); // 11
    for (int i=0; i<2; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<8; i++) // 000000
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x2); // 11
    for (int i=0; i<3; i++) // 0
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x2); // 11
    for (int i=0; i<3; i++) // 00
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<6; i++) // 00000
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x1); // 1
    for (int i=0; i<8; i++) // 00
        secp256k1_scalar_sqr_mont(t, t);
    secp256k1_scalar_mul_mont(t, t, &x6); // 111111

    secp256k1_scalar_from_mont(r, t);
}

#endif
