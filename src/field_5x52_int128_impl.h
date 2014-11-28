/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_FIELD_INNER5X52_IMPL_H_
#define _SECP256K1_FIELD_INNER5X52_IMPL_H_

#include <stdint.h>

#ifdef VERIFY
#define VERIFY_BITS(x, n) VERIFY_CHECK(((x) >> (n)) == 0)
#else
#define VERIFY_BITS(x, n) do { } while(0)
#endif

SECP256K1_INLINE static void secp256k1_fe_mul_inner(const uint64_t *a, const uint64_t *b, uint64_t *r) {
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
    /*  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  px is a shorthand for sum(a[i]*b[x-i], i=0..x).
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    __int128 c, d;

    d  = (__int128)a[0] * b[3]
       + (__int128)a[1] * b[2]
       + (__int128)a[2] * b[1]
       + (__int128)a[3] * b[0];
    VERIFY_BITS(d, 114);
    /* [d 0 0 0] = [p3 0 0 0] */
    c  = (__int128)a[4] * b[4];
    VERIFY_BITS(c, 112);
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    d += (c & M) * R; c >>= 52;
    VERIFY_BITS(d, 115);
    VERIFY_BITS(c, 60);
    /* [c 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    uint64_t t3 = d & M; d >>= 52;
    VERIFY_BITS(t3, 52);
    VERIFY_BITS(d, 63);
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    d += (__int128)a[0] * b[4]
       + (__int128)a[1] * b[3]
       + (__int128)a[2] * b[2]
       + (__int128)a[3] * b[1]
       + (__int128)a[4] * b[0];
    VERIFY_BITS(d, 115);
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    d += c * R;
    VERIFY_BITS(d, 116);
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    uint64_t t4 = d & M; d >>= 52;
    VERIFY_BITS(t4, 52);
    VERIFY_BITS(d, 64);
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    uint64_t tx = (t4 >> 48); t4 &= (M >> 4);
    VERIFY_BITS(tx, 4);
    VERIFY_BITS(t4, 48);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    c  = (__int128)a[0] * b[0];
    VERIFY_BITS(c, 112);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    d += (__int128)a[1] * b[4]
       + (__int128)a[2] * b[3]
       + (__int128)a[3] * b[2]
       + (__int128)a[4] * b[1];
    VERIFY_BITS(d, 115);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    uint64_t u0 = d & M; d >>= 52;
    VERIFY_BITS(u0, 52);
    VERIFY_BITS(d, 63);
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    VERIFY_BITS(u0, 56);
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    c += (__int128)u0 * (R >> 4);
    VERIFY_BITS(c, 115);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    uint64_t t0 = c & M; c >>= 52;
    VERIFY_BITS(t0, 52);
    VERIFY_BITS(c, 61);
    /* [d 0 t4 t3 0 c t0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    c += (__int128)a[0] * b[1]
       + (__int128)a[1] * b[0];
    VERIFY_BITS(c, 114);
    /* [d 0 t4 t3 0 c t0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    d += (__int128)a[2] * b[4]
       + (__int128)a[3] * b[3]
       + (__int128)a[4] * b[2];
    VERIFY_BITS(d, 114);
    /* [d 0 t4 t3 0 c t0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    c += (d & M) * R; d >>= 52;
    VERIFY_BITS(c, 115);
    VERIFY_BITS(d, 62);
    /* [d 0 0 t4 t3 0 c t0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    uint64_t t1 = c & M; c >>= 52;
    VERIFY_BITS(t1, 52);
    VERIFY_BITS(c, 63);
    /* [d 0 0 t4 t3 c t1 t0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    c += (__int128)a[0] * b[2]
       + (__int128)a[1] * b[1]
       + (__int128)a[2] * b[0];
    VERIFY_BITS(c, 114);
    /* [d 0 0 t4 t3 c t1 t0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    d += (__int128)a[3] * b[4]
       + (__int128)a[4] * b[3];
    VERIFY_BITS(d, 114);
    /* [d 0 0 t4 t3 c t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c += (d & M) * R; d >>= 52;
    VERIFY_BITS(c, 115);
    VERIFY_BITS(d, 62);
    /* [d 0 0 0 t4 t3 c t1 t0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    r[0] = t0;
    VERIFY_BITS(r[0], 52);
    /* [d 0 0 0 t4 t3 c t1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[1] = t1;
    VERIFY_BITS(r[1], 52);
    /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = c & M; c >>= 52;
    VERIFY_BITS(r[2], 52);
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += d * R + t3;;
    VERIFY_BITS(c, 100);
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = c & M; c >>= 52;
    VERIFY_BITS(r[3], 52);
    VERIFY_BITS(c, 48);
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += t4;
    VERIFY_BITS(c, 49);
    /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = c;
    VERIFY_BITS(r[4], 49);
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
}

SECP256K1_INLINE static void secp256k1_fe_sqr_inner(const uint64_t *a, uint64_t *r) {
    VERIFY_BITS(a[0], 56);
    VERIFY_BITS(a[1], 56);
    VERIFY_BITS(a[2], 56);
    VERIFY_BITS(a[3], 56);
    VERIFY_BITS(a[4], 52);

    const uint64_t M = 0xFFFFFFFFFFFFFULL, R = 0x1000003D10ULL;
    /**  [... a b c] is a shorthand for ... + a<<104 + b<<52 + c<<0 mod n.
     *  px is a shorthand for sum(a[i]*a[x-i], i=0..x).
     *  Note that [x 0 0 0 0 0] = [x*R].
     */

    __int128 c, d;

    uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];

    d  = (__int128)(a0*2) * a3
       + (__int128)(a1*2) * a2;
    VERIFY_BITS(d, 114);
    /* [d 0 0 0] = [p3 0 0 0] */
    c  = (__int128)a4 * a4;
    VERIFY_BITS(c, 112);
    /* [c 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    d += (c & M) * R; c >>= 52;
    VERIFY_BITS(d, 115);
    VERIFY_BITS(c, 60);
    /* [c 0 0 0 0 0 d 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */
    uint64_t t3 = d & M; d >>= 52;
    VERIFY_BITS(t3, 52);
    VERIFY_BITS(d, 63);
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 0 p3 0 0 0] */

    a4 *= 2;
    d += (__int128)a0 * a4
       + (__int128)(a1*2) * a3
       + (__int128)a2 * a2;
    VERIFY_BITS(d, 115);
    /* [c 0 0 0 0 d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    d += c * R;
    VERIFY_BITS(d, 116);
    /* [d t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    uint64_t t4 = d & M; d >>= 52;
    VERIFY_BITS(t4, 52);
    VERIFY_BITS(d, 64);
    /* [d t4 t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */
    uint64_t tx = (t4 >> 48); t4 &= (M >> 4);
    VERIFY_BITS(tx, 4);
    VERIFY_BITS(t4, 48);
    /* [d t4+(tx<<48) t3 0 0 0] = [p8 0 0 0 p4 p3 0 0 0] */

    c  = (__int128)a0 * a0;
    VERIFY_BITS(c, 112);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 0 p4 p3 0 0 p0] */
    d += (__int128)a1 * a4
       + (__int128)(a2*2) * a3;
    VERIFY_BITS(d, 114);
    /* [d t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    uint64_t u0 = d & M; d >>= 52;
    VERIFY_BITS(u0, 52);
    VERIFY_BITS(d, 62);
    /* [d u0 t4+(tx<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    /* [d 0 t4+(tx<<48)+(u0<<52) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    u0 = (u0 << 4) | tx;
    VERIFY_BITS(u0, 56);
    /* [d 0 t4+(u0<<48) t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    c += (__int128)u0 * (R >> 4);
    VERIFY_BITS(c, 113);
    /* [d 0 t4 t3 0 0 c] = [p8 0 0 p5 p4 p3 0 0 p0] */
    r[0] = c & M; c >>= 52;
    VERIFY_BITS(r[0], 52);
    VERIFY_BITS(c, 61);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 0 p0] */

    a0 *= 2;
    c += (__int128)a0 * a1;
    VERIFY_BITS(c, 114);
    /* [d 0 t4 t3 0 c r0] = [p8 0 0 p5 p4 p3 0 p1 p0] */
    d += (__int128)a2 * a4
       + (__int128)a3 * a3;
    VERIFY_BITS(d, 114);
    /* [d 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    c += (d & M) * R; d >>= 52;
    VERIFY_BITS(c, 115);
    VERIFY_BITS(d, 62);
    /* [d 0 0 t4 t3 0 c r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */
    r[1] = c & M; c >>= 52;
    VERIFY_BITS(r[1], 52);
    VERIFY_BITS(c, 63);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 0 p1 p0] */

    c += (__int128)a0 * a2
       + (__int128)a1 * a1;
    VERIFY_BITS(c, 114);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 0 p6 p5 p4 p3 p2 p1 p0] */
    d += (__int128)a3 * a4;
    VERIFY_BITS(d, 114);
    /* [d 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c += (d & M) * R; d >>= 52;
    VERIFY_BITS(c, 115);
    VERIFY_BITS(d, 62);
    /* [d 0 0 0 t4 t3 c r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[2] = c & M; c >>= 52;
    VERIFY_BITS(r[2], 52);
    VERIFY_BITS(c, 63);
    /* [d 0 0 0 t4 t3+c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */

    c   += d * R + t3;;
    VERIFY_BITS(c, 100);
    /* [t4 c r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[3] = c & M; c >>= 52;
    VERIFY_BITS(r[3], 52);
    VERIFY_BITS(c, 48);
    /* [t4+c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    c   += t4;
    VERIFY_BITS(c, 49);
    /* [c r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
    r[4] = c;
    VERIFY_BITS(r[4], 49);
    /* [r4 r3 r2 r1 r0] = [p8 p7 p6 p5 p4 p3 p2 p1 p0] */
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
