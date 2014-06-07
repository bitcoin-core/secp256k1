// Copyright (c) 2013 Pieter Wuille
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SECP256K1_FIELD_INNER5X52_IMPL_H_
#define _SECP256K1_FIELD_INNER5X52_IMPL_H_

#include <stdint.h>

void static inline secp256k1_fe_mul_inner(const uint64_t *a, const uint64_t *b, uint64_t *r) {
    __int128 c = (__int128)a[0] * b[0];
    uint64_t t0 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0FFFFFFFFFFFFFE0
    c = c + (__int128)a[0] * b[1] +
            (__int128)a[1] * b[0];
    uint64_t t1 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 20000000000000BF
    c = c + (__int128)a[0] * b[2] +
            (__int128)a[1] * b[1] +
            (__int128)a[2] * b[0];
    uint64_t t2 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 30000000000001A0
    c = c + (__int128)a[0] * b[3] +
            (__int128)a[1] * b[2] +
            (__int128)a[2] * b[1] +
            (__int128)a[3] * b[0];
    uint64_t t3 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 4000000000000280
    c = c + (__int128)a[0] * b[4] +
            (__int128)a[1] * b[3] +
            (__int128)a[2] * b[2] +
            (__int128)a[3] * b[1] +
            (__int128)a[4] * b[0];
    uint64_t t4 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 320000000000037E
    c = c + (__int128)a[1] * b[4] +
            (__int128)a[2] * b[3] +
            (__int128)a[3] * b[2] +
            (__int128)a[4] * b[1];
    uint64_t t5 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 22000000000002BE
    c = c + (__int128)a[2] * b[4] +
            (__int128)a[3] * b[3] +
            (__int128)a[4] * b[2];
    uint64_t t6 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 12000000000001DE
    c = c + (__int128)a[3] * b[4] +
            (__int128)a[4] * b[3];
    uint64_t t7 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 02000000000000FE
    c = c + (__int128)a[4] * b[4];
    uint64_t t8 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 001000000000001E
    uint64_t t9 = c;

    c = t0 + (__int128)t5 * 0x1000003D10ULL;
    t0 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t1 + (__int128)t6 * 0x1000003D10ULL;
    t1 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t2 + (__int128)t7 * 0x1000003D10ULL;
    r[2] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t3 + (__int128)t8 * 0x1000003D10ULL;
    r[3] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t4 + (__int128)t9 * 0x1000003D10ULL;
    r[4] = c & 0x0FFFFFFFFFFFFULL; c = c >> 48; // c max 000001000003D110
    c = t0 + (__int128)c * 0x1000003D1ULL;
    r[0] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 1000008
    r[1] = t1 + c;

}

void static inline secp256k1_fe_sqr_inner(const uint64_t *a, uint64_t *r) {
    __int128 c = (__int128)a[0] * a[0];
    uint64_t t0 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0FFFFFFFFFFFFFE0
    c = c + (__int128)(a[0]*2) * a[1];
    uint64_t t1 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 20000000000000BF
    c = c + (__int128)(a[0]*2) * a[2] +
            (__int128)a[1] * a[1];
    uint64_t t2 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 30000000000001A0
    c = c + (__int128)(a[0]*2) * a[3] +
            (__int128)(a[1]*2) * a[2];
    uint64_t t3 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 4000000000000280
    c = c + (__int128)(a[0]*2) * a[4] +
            (__int128)(a[1]*2) * a[3] +
            (__int128)a[2] * a[2];
    uint64_t t4 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 320000000000037E
    c = c + (__int128)(a[1]*2) * a[4] +
            (__int128)(a[2]*2) * a[3];
    uint64_t t5 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 22000000000002BE
    c = c + (__int128)(a[2]*2) * a[4] +
            (__int128)a[3] * a[3];
    uint64_t t6 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 12000000000001DE
    c = c + (__int128)(a[3]*2) * a[4];
    uint64_t t7 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 02000000000000FE
    c = c + (__int128)a[4] * a[4];
    uint64_t t8 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 001000000000001E
    uint64_t t9 = c;
    c = t0 + (__int128)t5 * 0x1000003D10ULL;
    t0 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t1 + (__int128)t6 * 0x1000003D10ULL;
    t1 = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t2 + (__int128)t7 * 0x1000003D10ULL;
    r[2] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t3 + (__int128)t8 * 0x1000003D10ULL;
    r[3] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 0000001000003D10
    c = c + t4 + (__int128)t9 * 0x1000003D10ULL;
    r[4] = c & 0x0FFFFFFFFFFFFULL; c = c >> 48; // c max 000001000003D110
    c = t0 + (__int128)c * 0x1000003D1ULL;
    r[0] = c & 0xFFFFFFFFFFFFFULL; c = c >> 52; // c max 1000008
    r[1] = t1 + c;

}

typedef unsigned __int128 uint128_t;

void static inline secp256k1_fec_mul_inner(const uint64_t *a, const uint64_t *b, uint64_t *r) {
    uint64_t b0 = b[0], b1 = b[1], b2 = b[2], b3 = b[3];

    uint128_t ai = a[0];
    uint128_t c = ai * b0;
    uint64_t t0 = (uint64_t)c; c >>= 64;
    c += ai * b1;
    uint64_t t1 = (uint64_t)c; c >>= 64;
    c += ai * b2;
    uint64_t t2 = (uint64_t)c; c >>= 64;
    c += ai * b3;
    uint64_t t3 = (uint64_t)c; c >>= 64;
    uint64_t t4 = (uint64_t)c;

    ai = a[1];
    c  = ai * b0 + t1;
    t1 = (uint64_t)c; c >>= 64;
    c += ai * b1 + t2;
    t2 = (uint64_t)c; c >>= 64;
    c += ai * b2 + t3;
    t3 = (uint64_t)c; c >>= 64;
    c += ai * b3 + t4;
    t4 = (uint64_t)c; c >>= 64;
    uint64_t t5 = (uint64_t)c;

    ai = a[2];
    c  = ai * b0 + t2;
    t2 = (uint64_t)c; c >>= 64;
    c += ai * b1 + t3;
    t3 = (uint64_t)c; c >>= 64;
    c += ai * b2 + t4;
    t4 = (uint64_t)c; c >>= 64;
    c += ai * b3 + t5;
    t5 = (uint64_t)c; c >>= 64;
    uint64_t t6 = (uint64_t)c;

    ai = a[3];
    c  = ai * b0 + t3;
    t3 = (uint64_t)c; c >>= 64;
    c += ai * b1 + t4;
    t4 = (uint64_t)c; c >>= 64;
    c += ai * b2 + t5;
    t5 = (uint64_t)c; c >>= 64;
    c += ai * b3 + t6;
    t6 = (uint64_t)c; c >>= 64;

    c *= 0x1000003D1ULL;
    c += t3; t3 = (uint64_t)c; c >>= 64;
    c += t4;
    c *= 0x1000003D1ULL;
    c += t0; t0 = (uint64_t)c; c >>= 64;

    c += (uint128_t)t5 * 0x1000003D1ULL + t1; t1 = (uint64_t)c; c >>= 64;
    c += (uint128_t)t6 * 0x1000003D1ULL + t2; t2 = (uint64_t)c; c >>= 64;

    c += t3; r[3] = (uint64_t)c; c >>= 64;
    c *= 0x1000003D1ULL;
    c += t0; r[0] = (uint64_t)c; c >>= 64;
    c += t1; r[1] = (uint64_t)c; c >>= 64;
    c += t2; r[2] = (uint64_t)c;
    assert((c >> 64) == 0);
}

void static inline secp256k1_fec_sqr_inner(const uint64_t *a, uint64_t *r) {
    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3];

    uint128_t m = (uint128_t)a1 * a2;
    uint128_t c = (uint128_t)a0 * a1;
    uint64_t t1 = (uint64_t)c; c >>= 64;
    c += (uint128_t)a0 * a2;
    uint64_t t2 = (uint64_t)c; c >>= 64;
    c += (uint128_t)a0 * a3 + (uint64_t)m;
    uint64_t t3 = (uint64_t)c; c >>= 64;
    c += (uint128_t)a1 * a3 + (uint64_t)(m >> 64);
    uint64_t t4 = (uint64_t)c; c >>= 64;
    c += (uint128_t)a2 * a3;
    uint64_t t5 = (uint64_t)c; c >>= 64;
    uint64_t t6 = (uint64_t)c;

    m  = (uint128_t)a0 * a0;
    uint64_t t0 = (uint64_t)m;
    c  = ((uint128_t)t1 << 1) + (uint64_t)(m >> 64);
    t1 = (uint64_t)c; c >>= 64;
    m  = (uint128_t)a1 * a1;
    c += ((uint128_t)t2 << 1) + (uint64_t)m;
    t2 = (uint64_t)c; c >>= 64;
    c += ((uint128_t)t3 << 1) + (uint64_t)(m >> 64);
    t3 = (uint64_t)c; c >>= 64;
    m  = (uint128_t)a2 * a2;
    c += ((uint128_t)t4 << 1) + (uint64_t)m;
    t4 = (uint64_t)c; c >>= 64;
    c += ((uint128_t)t5 << 1) + (uint64_t)(m >> 64);
    t5 = (uint64_t)c; c >>= 64;
    m  = (uint128_t)a3 * a3;
    c += ((uint128_t)t6 << 1) + (uint64_t)m;
    t6 = (uint64_t)c; c >>= 64;
    c += (uint64_t)(m >> 64);

    c *= 0x1000003D1ULL;
    c += t3; t3 = (uint64_t)c; c >>= 64;
    c += t4;
    c *= 0x1000003D1ULL;
    c += t0; t0 = (uint64_t)c; c >>= 64;

    c += (uint128_t)t5 * 0x1000003D1ULL + t1; t1 = (uint64_t)c; c >>= 64;
    c += (uint128_t)t6 * 0x1000003D1ULL + t2; t2 = (uint64_t)c; c >>= 64;

    c += t3; r[3] = (uint64_t)c; c >>= 64;
    c *= 0x1000003D1ULL;
    c += t0; r[0] = (uint64_t)c; c >>= 64;
    c += t1; r[1] = (uint64_t)c; c >>= 64;
    c += t2; r[2] = (uint64_t)c;
    assert((c >> 64) == 0);
}

#endif
