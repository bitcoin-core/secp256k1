// Copyright (c) 2013 Pieter Wuille
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SECP256K1_FIELD_INNER5X52_IMPL_H_
#define _SECP256K1_FIELD_INNER5X52_IMPL_H_

#include <stdint.h>

void static inline secp256k1_fe_mul_inner(const uint64_t *a, const uint64_t *b, uint64_t *r) {

    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

    __int128 c, d;

    d  = (__int128)a[0] * b[4]
       + (__int128)a[1] * b[3]
       + (__int128)a[2] * b[2]
       + (__int128)a[3] * b[1]
       + (__int128)a[4] * b[0];
    uint64_t t4 = d & M; d >>= 52;

    c  = (__int128)a[0] * b[0];
    d += (__int128)a[1] * b[4]
       + (__int128)a[2] * b[3]
       + (__int128)a[3] * b[2]
       + (__int128)a[4] * b[1];
    c += (d & M) * R; d >>= 52;
    uint64_t t0 = c & M; c >>= 52;

    c += (__int128)a[0] * b[1]
       + (__int128)a[1] * b[0];
    d += (__int128)a[2] * b[4]
       + (__int128)a[3] * b[3]
       + (__int128)a[4] * b[2];
    c += (d & M) * R; d >>= 52;
    uint64_t t1 = c & M; c >>= 52;

    c += (__int128)a[0] * b[2]
       + (__int128)a[1] * b[1]
       + (__int128)a[2] * b[0];
    d += (__int128)a[3] * b[4]
       + (__int128)a[4] * b[3];
    c += (d & M) * R; d >>= 52;
    uint64_t t2 = c & M; c >>= 52;

    c += (__int128)a[0] * b[3]
       + (__int128)a[1] * b[2]
       + (__int128)a[2] * b[1]
       + (__int128)a[3] * b[0];
    d += (__int128)a[4] * b[4];
    c += (d & M) * R; d >>= 52;

    r[2] = t2;
    r[3] = c & M; c >>= 52;
    c   += d * R + t4;
    r[4] = c & (M >> 4); c >>= 48;
    c   *= (R >> 4);
    c   += t0;
    r[0] = c & M; c >>= 52;
    c   += t1;
    r[1] = c;
}

void static inline secp256k1_fe_sqr_inner(const uint64_t *a, uint64_t *r) {

    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;

    __int128 c, d;

    d  = (__int128)(a[0]*2) * a[4]
       + (__int128)(a[1]*2) * a[3]
       + (__int128)a[2] * a[2];
    uint64_t t4 = d & M; d >>= 52;

    c  = (__int128)a[0] * a[0];
    d += (__int128)(a[1]*2) * a[4]
       + (__int128)(a[2]*2) * a[3];
    c += (d & M) * R; d >>= 52;
    uint64_t t0 = c & M; c >>= 52;

    c += (__int128)(a[0]*2) * a[1];
    d += (__int128)(a[2]*2) * a[4]
       + (__int128)a[3] * a[3];
    c += (d & M) * R; d >>= 52;
    uint64_t t1 = c & M; c >>= 52;

    c += (__int128)(a[0]*2) * a[2]
       + (__int128)a[1] * a[1];
    d += (__int128)(a[3]*2) * a[4];
    c += (d & M) * R; d >>= 52;
    uint64_t t2 = c & M; c >>= 52;

    c += (__int128)(a[0]*2) * a[3]
       + (__int128)(a[1]*2) * a[2];
    d += (__int128)a[4] * a[4];
    c += (d & M) * R; d >>= 52;

    r[2] = t2;
    r[3] = c & M; c >>= 52;
    c   += d * R + t4;
    r[4] = c & (M >> 4); c >>= 48;
    c   *= (R >> 4);
    c   += t0;
    r[0] = c & M; c >>= 52;
    c   += t1;
    r[1] = c;
}

#endif
