// Copyright (c) 2013 Pieter Wuille
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SECP256K1_FIELD_INNER5X52_IMPL_H_
#define _SECP256K1_FIELD_INNER5X52_IMPL_H_

#include <stdint.h>

#ifdef VERIFY
#define VERIFY_BITS(x, n) do { } while(0)
#else
#define VERIFY_BITS(x, n) VERIFY_CHECK(((x) >> (n)) == 0)
#endif

void static inline secp256k1_fe_mul_inner(const uint64_t *a, const uint64_t *b, uint64_t *r) {
    VERIFY_BITS(a[0], 56);
    VERIFY_BITS(a[1], 56);
    VERIFY_BITS(a[2], 56);
    VERIFY_BITS(a[3], 56);
    VERIFY_BITS(a[4], 52);
    VERIFY_BITS(b[0], 56);
    VERIFY_BITS(b[1], 56);
    VERIFY_BITS(b[2], 56);
    VERIFY_BITS(b[3], 56);
    VERIFY_BITS(b[4], 52);

    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;
    // [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0.
    // px is a shorthand for sum(a[i]*b[x-i], i=0..x).
    // Note that [x 0 0 0 0 0] = [x*R] mod n.

    __int128 c, d;

    d  = (__int128)a[0] * b[4]
       + (__int128)a[1] * b[3]
       + (__int128)a[2] * b[2]
       + (__int128)a[3] * b[1]
       + (__int128)a[4] * b[0];
    // [d 0 0 0 0] = [p4 0 0 0 0]
    VERIFY_BITS(d, 114);
    uint64_t t4 = d & M; d >>= 52;
    // [d t4 0 0 0 0] = [p4 0 0 0 0]
    VERIFY_BITS(d, 62);

    c  = (__int128)a[0] * b[0];
    // [d t4 0 0 0 c] = [p4 0 0 0 p0]
    VERIFY_BITS(c, 112);
    d += (__int128)a[1] * b[4]
       + (__int128)a[2] * b[3]
       + (__int128)a[3] * b[2]
       + (__int128)a[4] * b[1];
    // [d t4 0 0 0 c] = [p5 p4 0 0 0 p0]
    VERIFY_BITS(d, 114);
    c += (d & M) * R; d >>= 52;
    // [d 0 t4 0 0 0 c] = [p5 p4 0 0 0 p0]
    VERIFY_BITS(c, 113);
    VERIFY_BITS(d, 62);
    uint64_t t0 = c & M; c >>= 52;
    // [d 0 t4 0 0 c t0] = [p5 p4 0 0 0 p0]
    VERIFY_BITS(c, 61);

    c += (__int128)a[0] * b[1]
       + (__int128)a[1] * b[0];
    // [d 0 t4 0 0 c t0] = [p5 p4 0 0 p1 p0]
    VERIFY_BITS(c, 113);
    d += (__int128)a[2] * b[4]
       + (__int128)a[3] * b[3]
       + (__int128)a[4] * b[2];
    // [d 0 t4 0 0 c t0] = [p6 p5 p4 0 0 p1 p0]
    VERIFY_BITS(d, 113);
    c += (d & M) * R; d >>= 52;
    // [d 0 0 t4 0 0 c t0] = [p6 p5 p4 0 0 p1 p0]
    VERIFY_BITS(c, 113);
    VERIFY_BITS(d, 61);
    uint64_t t1 = c & M; c >>= 52;
    // [d 0 0 t4 0 c t1 t0] = [p6 p5 p4 0 0 p1 p0]
    VERIFY_BITS(c, 61);

    c += (__int128)a[0] * b[2]
       + (__int128)a[1] * b[1]
       + (__int128)a[2] * b[0];
    // [d 0 0 t4 0 c t1 t0] = [p6 p5 p4 0 p2 p1 p0]
    VERIFY_BITS(c, 114);
    d += (__int128)a[3] * b[4]
       + (__int128)a[4] * b[3];
    // [d 0 0 t4 0 c t1 t0] = [p7 p6 p5 p5 p4 0 p2 p1 p0]
    VERIFY_BITS(d, 110);
    c += (d & M) * R; d >>= 52;
    // [d 0 0 0 t4 0 c t1 t0] = [p7 p6 p5 p4 0 p2 p1 p0]
    VERIFY_BITS(d, 58);
    uint64_t t2 = c & M; c >>= 52;
    // [d 0 0 0 t4 c t2 t1 t0] = [p7 p6 p5 p4 0 p2 p1 p0]
    VERIFY_BITS(c, 62);

    c += (__int128)a[0] * b[3]
       + (__int128)a[1] * b[2]
       + (__int128)a[2] * b[1]
       + (__int128)a[3] * b[0];
    // [d 0 0 0 t4 c t2 t1 t0] = [p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 114);
    d += (__int128)a[4] * b[4];
    // [d 0 0 0 t4 c t2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(d, 113);
    c += (d & M) * R; d >>= 52;
    // [d 0 0 0 0 t4 c t2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(d, 61);

    r[2] = t2;
    // [d 0 0 0 0 t4 c r2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r[3] = c & M; c >>= 52;
    // [d 0 0 0 0 c+t4 r3 r2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 52);
    c   += d * R + t4;
    // [c r3 r2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 89);
    r[4] = c & (M >> 4); c >>= 48;
    // [r4+(c<<48) r3 r2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 41);
    c   *= (R >> 4);
    // [r4 r3 r2 t1 t0+c] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 81);
    c   += t0;
    // [r4 r3 r2 t1 c] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r[0] = c & M; c >>= 52;
    // [r4 r3 r2 t1+c r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 29);
    c   += t1;
    // [r4 r3 r2 c r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 53);
    r[1] = c;
    // [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
}

void static inline secp256k1_fe_sqr_inner(const uint64_t *a, uint64_t *r) {
    VERIFY_BITS(a[0], 56);
    VERIFY_BITS(a[1], 56);
    VERIFY_BITS(a[2], 56);
    VERIFY_BITS(a[3], 56);
    VERIFY_BITS(a[4], 52);

    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;
    // [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0.
    // px is a shorthand for sum(a[i]*a[x-i], i=0..x).
    // Note that [x 0 0 0 0 0] = [x*R] mod n.

    __int128 c, d;

    d  = (__int128)(a[0]*2) * a[4]
       + (__int128)(a[1]*2) * a[3]
       + (__int128)a[2] * a[2];
    // [d 0 0 0 0] = [p4 0 0 0 0]
    VERIFY_BITS(d, 114);
    uint64_t t4 = d & M; d >>= 52;
    // [d t4 0 0 0 0] = [p4 0 0 0 0]
    VERIFY_BITS(d, 62);

    c  = (__int128)a[0] * a[0];
    // [d t4 0 0 0 c] = [p4 0 0 0 p0]
    VERIFY_BITS(c, 112);
    d += (__int128)(a[1]*2) * a[4]
       + (__int128)(a[2]*2) * a[3];
    // [d t4 0 0 0 c] = [p5 p4 0 0 0 p0]
    VERIFY_BITS(d, 114);
    c += (d & M) * R; d >>= 52;
    // [d 0 t4 0 0 0 c] = [p5 p4 0 0 0 p0]
    VERIFY_BITS(c, 113);
    VERIFY_BITS(d, 62);
    uint64_t t0 = c & M; c >>= 52;
    // [d 0 t4 0 0 c t0] = [p5 p4 0 0 0 p0]
    VERIFY_BITS(c, 61);

    c += (__int128)(a[0]*2) * a[1];
    // [d 0 t4 0 0 c t0] = [p5 p4 0 0 p1 p0]
    VERIFY_BITS(c, 113);
    d += (__int128)(a[2]*2) * a[4]
       + (__int128)a[3] * a[3];
    // [d 0 t4 0 0 c t0] = [p6 p5 p4 0 0 p1 p0]
    VERIFY_BITS(d, 113);
    c += (d & M) * R; d >>= 52;
    // [d 0 0 t4 0 0 c t0] = [p6 p5 p4 0 0 p1 p0]
    VERIFY_BITS(c, 113);
    VERIFY_BITS(d, 61);
    uint64_t t1 = c & M; c >>= 52;
    // [d 0 0 t4 0 c t1 t0] = [p6 p5 p4 0 0 p1 p0]
    VERIFY_BITS(c, 61);

    c += (__int128)(a[0]*2) * a[2]
       + (__int128)a[1] * a[1];
    // [d 0 0 t4 0 c t1 t0] = [p6 p5 p4 0 p2 p1 p0]
    VERIFY_BITS(c, 114);
    d += (__int128)(a[3]*2) * a[4];
    // [d 0 0 t4 0 c t1 t0] = [p7 p6 p5 p5 p4 0 p2 p1 p0]
    VERIFY_BITS(d, 110);
    c += (d & M) * R; d >>= 52;
    // [d 0 0 0 t4 0 c t1 t0] = [p7 p6 p5 p4 0 p2 p1 p0]
    VERIFY_BITS(d, 58);
    uint64_t t2 = c & M; c >>= 52;
    // [d 0 0 0 t4 c t2 t1 t0] = [p7 p6 p5 p4 0 p2 p1 p0]
    VERIFY_BITS(c, 62);

    c += (__int128)(a[0]*2) * a[3]
       + (__int128)(a[1]*2) * a[2];
    // [d 0 0 0 t4 c t2 t1 t0] = [p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 114);
    d += (__int128)a[4] * a[4];
    // [d 0 0 0 t4 c t2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(d, 113);
    c += (d & M) * R; d >>= 52;
    // [d 0 0 0 0 t4 c t2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(d, 61);

    r[2] = t2;
    // [d 0 0 0 0 t4 c r2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r[3] = c & M; c >>= 52;
    // [d 0 0 0 0 c+t4 r3 r2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 52);
    c   += d * R + t4;
    // [c r3 r2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 89);
    r[4] = c & (M >> 4); c >>= 48;
    // [r4+(c<<48) r3 r2 t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 41);
    c   *= (R >> 4);
    // [r4 r3 r2 t1 t0+c] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 81);
    c   += t0;
    // [r4 r3 r2 t1 c] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    r[0] = c & M; c >>= 52;
    // [r4 r3 r2 t1+c r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 29);
    c   += t1;
    // [r4 r3 r2 c r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
    VERIFY_BITS(c, 53);
    r[1] = c;
    // [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0]
}

#endif
