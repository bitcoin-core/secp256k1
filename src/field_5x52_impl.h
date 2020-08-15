/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_FIELD_REPR_IMPL_H
#define SECP256K1_FIELD_REPR_IMPL_H

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "util.h"
#include "field.h"

#if defined(USE_ASM_X86_64)
#include "field_5x52_asm_impl.h"
#else
#include "field_5x52_int128_impl.h"
#endif

/** Implements arithmetic modulo FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFF FFFFFFFE FFFFFC2F,
 *  represented as 5 uint64_t's in base 2^52. The values are allowed to contain >52 each. In particular,
 *  each FieldElem has a 'magnitude' associated with it. Internally, a magnitude M means each element
 *  is at most M*(2^53-1), except the most significant one, which is limited to M*(2^49-1). All operations
 *  accept any input with magnitude at most M, and have different rules for propagating magnitude to their
 *  output.
 */

#ifdef VERIFY
static void secp256k1_fe_verify(const secp256k1_fe *a) {
    const uint64_t *d = a->n;
    int m = a->normalized ? 1 : 2 * a->magnitude, r = 1;
   /* secp256k1 'p' value defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    r &= (d[0] <= 0xFFFFFFFFFFFFFULL * m);
    r &= (d[1] <= 0xFFFFFFFFFFFFFULL * m);
    r &= (d[2] <= 0xFFFFFFFFFFFFFULL * m);
    r &= (d[3] <= 0xFFFFFFFFFFFFFULL * m);
    r &= (d[4] <= 0x0FFFFFFFFFFFFULL * m);
    r &= (a->magnitude >= 0);
    r &= (a->magnitude <= 2048);
    if (a->normalized) {
        r &= (a->magnitude <= 1);
        if (r && (d[4] == 0x0FFFFFFFFFFFFULL) && ((d[3] & d[2] & d[1]) == 0xFFFFFFFFFFFFFULL)) {
            r &= (d[0] < 0xFFFFEFFFFFC2FULL);
        }
    }
    VERIFY_CHECK(r == 1);
}
#endif

static void secp256k1_fe_normalize(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t m;
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; m = t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; m &= t3;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFFULL) & (m == 0xFFFFFFFFFFFFFULL)
        & (t0 >= 0xFFFFEFFFFFC2FULL));

    /* Apply the final reduction (for constant-time behaviour, we do it always) */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

    /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
    VERIFY_CHECK(t4 >> 48 == x);

    /* Mask off the possible multiple of 2^256 from the final reduction */
    t4 &= 0x0FFFFFFFFFFFFULL;

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_normalize_weak(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;

#ifdef VERIFY
    r->magnitude = 1;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_normalize_var(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t m;
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; m = t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; m &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; m &= t3;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    /* At most a single final reduction is needed; check if the value is >= the field characteristic */
    x = (t4 >> 48) | ((t4 == 0x0FFFFFFFFFFFFULL) & (m == 0xFFFFFFFFFFFFFULL)
        & (t0 >= 0xFFFFEFFFFFC2FULL));

    if (x) {
        t0 += 0x1000003D1ULL;
        t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL;
        t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL;
        t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL;
        t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL;

        /* If t4 didn't carry to bit 48 already, then it should have after any final reduction */
        VERIFY_CHECK(t4 >> 48 == x);

        /* Mask off the possible multiple of 2^256 from the final reduction */
        t4 &= 0x0FFFFFFFFFFFFULL;
    }

    r->n[0] = t0; r->n[1] = t1; r->n[2] = t2; r->n[3] = t3; r->n[4] = t4;

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

static int secp256k1_fe_normalizes_to_zero(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    uint64_t z0, z1;

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    uint64_t x = t4 >> 48; t4 &= 0x0FFFFFFFFFFFFULL;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;
    t1 += (t0 >> 52); t0 &= 0xFFFFFFFFFFFFFULL; z0  = t0; z1  = t0 ^ 0x1000003D0ULL;
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; z0 |= t1; z1 &= t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; z0 |= t3; z1 &= t3;
                                                z0 |= t4; z1 &= t4 ^ 0xF000000000000ULL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFFULL);
}

static int secp256k1_fe_normalizes_to_zero_var(secp256k1_fe *r) {
    uint64_t t0, t1, t2, t3, t4;
    uint64_t z0, z1;
    uint64_t x;

    t0 = r->n[0];
    t4 = r->n[4];

    /* Reduce t4 at the start so there will be at most a single carry from the first pass */
    x = t4 >> 48;

    /* The first pass ensures the magnitude is 1, ... */
    t0 += x * 0x1000003D1ULL;

    /* z0 tracks a possible raw value of 0, z1 tracks a possible raw value of P */
    z0 = t0 & 0xFFFFFFFFFFFFFULL;
    z1 = z0 ^ 0x1000003D0ULL;

    /* Fast return path should catch the majority of cases */
    if ((z0 != 0ULL) & (z1 != 0xFFFFFFFFFFFFFULL)) {
        return 0;
    }

    t1 = r->n[1];
    t2 = r->n[2];
    t3 = r->n[3];

    t4 &= 0x0FFFFFFFFFFFFULL;

    t1 += (t0 >> 52);
    t2 += (t1 >> 52); t1 &= 0xFFFFFFFFFFFFFULL; z0 |= t1; z1 &= t1;
    t3 += (t2 >> 52); t2 &= 0xFFFFFFFFFFFFFULL; z0 |= t2; z1 &= t2;
    t4 += (t3 >> 52); t3 &= 0xFFFFFFFFFFFFFULL; z0 |= t3; z1 &= t3;
                                                z0 |= t4; z1 &= t4 ^ 0xF000000000000ULL;

    /* ... except for a possible carry at bit 48 of t4 (i.e. bit 256 of the field element) */
    VERIFY_CHECK(t4 >> 49 == 0);

    return (z0 == 0) | (z1 == 0xFFFFFFFFFFFFFULL);
}

SECP256K1_INLINE static void secp256k1_fe_set_int(secp256k1_fe *r, int a) {
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

SECP256K1_INLINE static int secp256k1_fe_is_zero(const secp256k1_fe *a) {
    const uint64_t *t = a->n;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    return (t[0] | t[1] | t[2] | t[3] | t[4]) == 0;
}

SECP256K1_INLINE static int secp256k1_fe_is_odd(const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    return a->n[0] & 1;
}

SECP256K1_INLINE static void secp256k1_fe_clear(secp256k1_fe *a) {
    int i;
#ifdef VERIFY
    a->magnitude = 0;
    a->normalized = 1;
#endif
    for (i=0; i<5; i++) {
        a->n[i] = 0;
    }
}

static int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    int i;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    VERIFY_CHECK(b->normalized);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b);
#endif
    for (i = 4; i >= 0; i--) {
        if (a->n[i] > b->n[i]) {
            return 1;
        }
        if (a->n[i] < b->n[i]) {
            return -1;
        }
    }
    return 0;
}

static int secp256k1_fe_set_b32(secp256k1_fe *r, const unsigned char *a) {
    int ret;
    r->n[0] = (uint64_t)a[31]
            | ((uint64_t)a[30] << 8)
            | ((uint64_t)a[29] << 16)
            | ((uint64_t)a[28] << 24)
            | ((uint64_t)a[27] << 32)
            | ((uint64_t)a[26] << 40)
            | ((uint64_t)(a[25] & 0xF)  << 48);
    r->n[1] = (uint64_t)((a[25] >> 4) & 0xF)
            | ((uint64_t)a[24] << 4)
            | ((uint64_t)a[23] << 12)
            | ((uint64_t)a[22] << 20)
            | ((uint64_t)a[21] << 28)
            | ((uint64_t)a[20] << 36)
            | ((uint64_t)a[19] << 44);
    r->n[2] = (uint64_t)a[18]
            | ((uint64_t)a[17] << 8)
            | ((uint64_t)a[16] << 16)
            | ((uint64_t)a[15] << 24)
            | ((uint64_t)a[14] << 32)
            | ((uint64_t)a[13] << 40)
            | ((uint64_t)(a[12] & 0xF) << 48);
    r->n[3] = (uint64_t)((a[12] >> 4) & 0xF)
            | ((uint64_t)a[11] << 4)
            | ((uint64_t)a[10] << 12)
            | ((uint64_t)a[9]  << 20)
            | ((uint64_t)a[8]  << 28)
            | ((uint64_t)a[7]  << 36)
            | ((uint64_t)a[6]  << 44);
    r->n[4] = (uint64_t)a[5]
            | ((uint64_t)a[4] << 8)
            | ((uint64_t)a[3] << 16)
            | ((uint64_t)a[2] << 24)
            | ((uint64_t)a[1] << 32)
            | ((uint64_t)a[0] << 40);
    ret = !((r->n[4] == 0x0FFFFFFFFFFFFULL) & ((r->n[3] & r->n[2] & r->n[1]) == 0xFFFFFFFFFFFFFULL) & (r->n[0] >= 0xFFFFEFFFFFC2FULL));
#ifdef VERIFY
    r->magnitude = 1;
    if (ret) {
        r->normalized = 1;
        secp256k1_fe_verify(r);
    } else {
        r->normalized = 0;
    }
#endif
    return ret;
}

/** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
static void secp256k1_fe_get_b32(unsigned char *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    r[0] = (a->n[4] >> 40) & 0xFF;
    r[1] = (a->n[4] >> 32) & 0xFF;
    r[2] = (a->n[4] >> 24) & 0xFF;
    r[3] = (a->n[4] >> 16) & 0xFF;
    r[4] = (a->n[4] >> 8) & 0xFF;
    r[5] = a->n[4] & 0xFF;
    r[6] = (a->n[3] >> 44) & 0xFF;
    r[7] = (a->n[3] >> 36) & 0xFF;
    r[8] = (a->n[3] >> 28) & 0xFF;
    r[9] = (a->n[3] >> 20) & 0xFF;
    r[10] = (a->n[3] >> 12) & 0xFF;
    r[11] = (a->n[3] >> 4) & 0xFF;
    r[12] = ((a->n[2] >> 48) & 0xF) | ((a->n[3] & 0xF) << 4);
    r[13] = (a->n[2] >> 40) & 0xFF;
    r[14] = (a->n[2] >> 32) & 0xFF;
    r[15] = (a->n[2] >> 24) & 0xFF;
    r[16] = (a->n[2] >> 16) & 0xFF;
    r[17] = (a->n[2] >> 8) & 0xFF;
    r[18] = a->n[2] & 0xFF;
    r[19] = (a->n[1] >> 44) & 0xFF;
    r[20] = (a->n[1] >> 36) & 0xFF;
    r[21] = (a->n[1] >> 28) & 0xFF;
    r[22] = (a->n[1] >> 20) & 0xFF;
    r[23] = (a->n[1] >> 12) & 0xFF;
    r[24] = (a->n[1] >> 4) & 0xFF;
    r[25] = ((a->n[0] >> 48) & 0xF) | ((a->n[1] & 0xF) << 4);
    r[26] = (a->n[0] >> 40) & 0xFF;
    r[27] = (a->n[0] >> 32) & 0xFF;
    r[28] = (a->n[0] >> 24) & 0xFF;
    r[29] = (a->n[0] >> 16) & 0xFF;
    r[30] = (a->n[0] >> 8) & 0xFF;
    r[31] = a->n[0] & 0xFF;
}

SECP256K1_INLINE static void secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a, int m) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= m);
    secp256k1_fe_verify(a);
#endif
    r->n[0] = 0xFFFFEFFFFFC2FULL * 2 * (m + 1) - a->n[0];
    r->n[1] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[1];
    r->n[2] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[2];
    r->n[3] = 0xFFFFFFFFFFFFFULL * 2 * (m + 1) - a->n[3];
    r->n[4] = 0x0FFFFFFFFFFFFULL * 2 * (m + 1) - a->n[4];
#ifdef VERIFY
    r->magnitude = m + 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

SECP256K1_INLINE static void secp256k1_fe_mul_int(secp256k1_fe *r, int a) {
    r->n[0] *= a;
    r->n[1] *= a;
    r->n[2] *= a;
    r->n[3] *= a;
    r->n[4] *= a;
#ifdef VERIFY
    r->magnitude *= a;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

SECP256K1_INLINE static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) {
#ifdef VERIFY
    secp256k1_fe_verify(a);
#endif
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
#ifdef VERIFY
    r->magnitude += a->magnitude;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 8);
    VERIFY_CHECK(b->magnitude <= 8);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b);
    VERIFY_CHECK(r != b);
    VERIFY_CHECK(a != b);
#endif
    secp256k1_fe_mul_inner(r->n, a->n, b->n);
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 8);
    secp256k1_fe_verify(a);
#endif
    secp256k1_fe_sqr_inner(r->n, a->n);
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static SECP256K1_INLINE void secp256k1_fe_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag) {
    uint64_t mask0, mask1;
    VG_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = flag + ~((uint64_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
#ifdef VERIFY
    if (flag) {
        r->magnitude = a->magnitude;
        r->normalized = a->normalized;
    }
#endif
}

static SECP256K1_INLINE void secp256k1_fe_storage_cmov(secp256k1_fe_storage *r, const secp256k1_fe_storage *a, int flag) {
    uint64_t mask0, mask1;
    VG_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = flag + ~((uint64_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
}

static void secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif
    r->n[0] = a->n[0] | a->n[1] << 52;
    r->n[1] = a->n[1] >> 12 | a->n[2] << 40;
    r->n[2] = a->n[2] >> 24 | a->n[3] << 28;
    r->n[3] = a->n[3] >> 36 | a->n[4] << 16;
}

static SECP256K1_INLINE void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a) {
    r->n[0] = a->n[0] & 0xFFFFFFFFFFFFFULL;
    r->n[1] = a->n[0] >> 52 | ((a->n[1] << 12) & 0xFFFFFFFFFFFFFULL);
    r->n[2] = a->n[1] >> 40 | ((a->n[2] << 24) & 0xFFFFFFFFFFFFFULL);
    r->n[3] = a->n[2] >> 28 | ((a->n[3] << 36) & 0xFFFFFFFFFFFFFULL);
    r->n[4] = a->n[3] >> 16;
#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 1;
#endif
}

static void secp256k1_fe_decode_62(secp256k1_fe *r, const int64_t *a) {

    const uint64_t M52 = UINT64_MAX >> 12;
    const uint64_t a0 = a[0], a1 = a[1], a2 = a[2], a3 = a[3], a4 = a[4];
    uint64_t r0, r1, r2, r3, r4, t;

    t = (int64_t)a4 >> 8;

    /* a must be in the range [-2^256, 2^256). */
    VERIFY_CHECK(a0 >> 62 == 0);
    VERIFY_CHECK(a1 >> 62 == 0);
    VERIFY_CHECK(a2 >> 62 == 0);
    VERIFY_CHECK(a3 >> 62 == 0);
    VERIFY_CHECK(t == 0 || t == -(uint64_t)1);

    /* Add 2P if a4 is "negative". */
    r0  = 0xFFFFDFFFFF85EULL & t;
    r1  = 0xFFFFFFFFFFFFFULL & t;
    r2  = 0xFFFFFFFFFFFFFULL & t;
    r3  = 0xFFFFFFFFFFFFFULL & t;
    r4  = 0x1FFFFFFFFFFFFULL & t;

    r0 +=  a0                   & M52;
    r1 += (a0 >> 52 | a1 << 10) & M52;
    r2 += (a1 >> 42 | a2 << 20) & M52;
    r3 += (a2 >> 32 | a3 << 30) & M52;
    r4 += (a3 >> 22 | a4 << 40);

    r->n[0] = r0;
    r->n[1] = r1;
    r->n[2] = r2;
    r->n[3] = r3;
    r->n[4] = r4;

#ifdef VERIFY
    r->magnitude = 1;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_encode_62(int64_t *r, const secp256k1_fe *a) {

    const uint64_t M62 = UINT64_MAX >> 2;
    const uint64_t *n = &a->n[0];
    const uint64_t a0 = n[0], a1 = n[1], a2 = n[2], a3 = n[3], a4 = n[4];

#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif

    r[0] = (a0       | a1 << 52) & M62;
    r[1] = (a1 >> 10 | a2 << 42) & M62;
    r[2] = (a2 >> 20 | a3 << 32) & M62;
    r[3] = (a3 >> 30 | a4 << 22) & M62;
    r[4] =  a4 >> 40;
}

static uint64_t secp256k1_fe_divsteps_62(uint64_t eta, uint64_t f0, uint64_t g0, int64_t *t) {

    uint64_t u = -(uint64_t)1, v = 0, q = 0, r = -(uint64_t)1;
    uint64_t c1, c2, f = f0, g = g0, x, y, z;
    int i;

    for (i = 0; i < 62; ++i) {

        VERIFY_CHECK((f & 1) == 1);
        VERIFY_CHECK((u * f0 + v * g0) == -f << i);
        VERIFY_CHECK((q * f0 + r * g0) == -g << i);

        c1 = -(g & (eta >> 63));

        x = (f ^ g) & c1;
        f ^= x; g ^= x; g ^= c1; g -= c1;

        y = (u ^ q) & c1;
        u ^= y; q ^= y; q ^= c1; q -= c1;

        z = (v ^ r) & c1;
        v ^= z; r ^= z; r ^= c1; r -= c1;

        eta = (eta ^ c1) - c1 - 1;

        c2 = -(g & 1);

        g += (f & c2); g >>= 1;
        q += (u & c2); u <<= 1;
        r += (v & c2); v <<= 1;
    }

    t[0] = (int64_t)u;
    t[1] = (int64_t)v;
    t[2] = (int64_t)q;
    t[3] = (int64_t)r;

    return eta;
}

static uint64_t secp256k1_fe_divsteps_62_var(uint64_t eta, uint64_t f0, uint64_t g0, int64_t *t) {

#if 1
    static const uint8_t debruijn[64] = {
        0, 1, 2, 53, 3, 7, 54, 27, 4, 38, 41, 8, 34, 55, 48, 28,
        62, 5, 39, 46, 44, 42, 22, 9, 24, 35, 59, 56, 49, 18, 29, 11,
        63, 52, 6, 26, 37, 40, 33, 47, 61, 45, 43, 21, 23, 58, 17, 10,
        51, 25, 36, 32, 60, 20, 57, 16, 50, 31, 19, 15, 30, 14, 13, 12
    };
#endif

    uint64_t u = -(uint64_t)1, v = 0, q = 0, r = -(uint64_t)1;
    uint64_t f = f0, g = g0, m, w, x, y, z;
    int i = 62, limit, zeros;

    for (;;) {

        x = g | (UINT64_MAX << i);

        /* Use a sentinel bit to count zeros only up to i. */
#if 0
        zeros = __builtin_ctzll(x);
#else
        zeros = debruijn[((x & -x) * 0x022FDD63CC95386D) >> 58];
#endif

        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros;
        i -= zeros;

        if (i <= 0) {
            break;
        }

        VERIFY_CHECK((f & 1) == 1);
        VERIFY_CHECK((g & 1) == 1);
        VERIFY_CHECK((u * f0 + v * g0) == -f << (62 - i));
        VERIFY_CHECK((q * f0 + r * g0) == -g << (62 - i));

        if ((int64_t)eta < 0) {
            eta = -eta;
            x = f; f = g; g = -x;
            y = u; u = q; q = -y;
            z = v; v = r; r = -z;

            /* Handle up to 6 divsteps at once, subject to eta and i. */
            limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
            m = (UINT64_MAX >> (64 - limit)) & 63U;

            w = (f * g * (f * f - 2)) & m;
        } else {
            /* Handle up to 4 divsteps at once, subject to eta and i. */
            limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
            m = (UINT64_MAX >> (64 - limit)) & 15U;

            w = f + (((f + 1) & 4) << 1);
            w = (-w * g) & m;
        }

        g += f * w;
        q += u * w;
        r += v * w;

        VERIFY_CHECK((g & m) == 0);
    }

    t[0] = (int64_t)u;
    t[1] = (int64_t)v;
    t[2] = (int64_t)q;
    t[3] = (int64_t)r;

    return eta;
}

static void secp256k1_fe_update_de_62(int64_t *d, int64_t *e, const int64_t *t) {

    /* P == 2^256 - C62 */
    const int64_t C62 = 0x1000003D1LL;
    /* I62 == -P^-1 mod 2^62 */
    const int64_t I62 = 0x1838091DD2253531LL;
    const int64_t M62 = (int64_t)(UINT64_MAX >> 2);
    const int64_t d0 = d[0], d1 = d[1], d2 = d[2], d3 = d[3], d4 = d[4];
    const int64_t e0 = e[0], e1 = e[1], e2 = e[2], e3 = e[3], e4 = e[4];
    const int64_t u = t[0], v = t[1], q = t[2], r = t[3];
    int64_t md, me;
    int128_t cd = 0, ce = 0;

    cd -= (int128_t)u * d0 + (int128_t)v * e0;
    ce -= (int128_t)q * d0 + (int128_t)r * e0;

    /* Calculate the multiples of P to add, to zero the 62 bottom bits. We choose md, me
     * from the centred range [-2^61, 2^61) to keep d, e within [-2^256, 2^256). */
    md = (I62 * 4 * (int64_t)cd) >> 2;
    me = (I62 * 4 * (int64_t)ce) >> 2;

    cd -= (int128_t)C62 * md;
    ce -= (int128_t)C62 * me;

    VERIFY_CHECK(((int64_t)cd & M62) == 0); cd >>= 62;
    VERIFY_CHECK(((int64_t)ce & M62) == 0); ce >>= 62;

    cd -= (int128_t)u * d1 + (int128_t)v * e1;
    ce -= (int128_t)q * d1 + (int128_t)r * e1;

    d[0] = (int64_t)cd & M62; cd >>= 62;
    e[0] = (int64_t)ce & M62; ce >>= 62;

    cd -= (int128_t)u * d2 + (int128_t)v * e2;
    ce -= (int128_t)q * d2 + (int128_t)r * e2;

    d[1] = (int64_t)cd & M62; cd >>= 62;
    e[1] = (int64_t)ce & M62; ce >>= 62;

    cd -= (int128_t)u * d3 + (int128_t)v * e3;
    ce -= (int128_t)q * d3 + (int128_t)r * e3;

    d[2] = (int64_t)cd & M62; cd >>= 62;
    e[2] = (int64_t)ce & M62; ce >>= 62;

    cd -= (int128_t)u * d4 + (int128_t)v * e4;
    ce -= (int128_t)q * d4 + (int128_t)r * e4;

    cd += (int128_t)256 * md;
    ce += (int128_t)256 * me;

    d[3] = (int64_t)cd & M62; cd >>= 62;
    e[3] = (int64_t)ce & M62; ce >>= 62;

    d[4] = (int64_t)cd;
    e[4] = (int64_t)ce;
}

static void secp256k1_fe_update_fg_62(int64_t *f, int64_t *g, const int64_t *t) {

    const int64_t M62 = (int64_t)(UINT64_MAX >> 2);
    const int64_t f0 = f[0], f1 = f[1], f2 = f[2], f3 = f[3], f4 = f[4];
    const int64_t g0 = g[0], g1 = g[1], g2 = g[2], g3 = g[3], g4 = g[4];
    const int64_t u = t[0], v = t[1], q = t[2], r = t[3];
    int128_t cf = 0, cg = 0;

    cf -= (int128_t)u * f0 + (int128_t)v * g0;
    cg -= (int128_t)q * f0 + (int128_t)r * g0;

    VERIFY_CHECK(((int64_t)cf & M62) == 0); cf >>= 62;
    VERIFY_CHECK(((int64_t)cg & M62) == 0); cg >>= 62;

    cf -= (int128_t)u * f1 + (int128_t)v * g1;
    cg -= (int128_t)q * f1 + (int128_t)r * g1;

    f[0] = (int64_t)cf & M62; cf >>= 62;
    g[0] = (int64_t)cg & M62; cg >>= 62;

    cf -= (int128_t)u * f2 + (int128_t)v * g2;
    cg -= (int128_t)q * f2 + (int128_t)r * g2;

    f[1] = (int64_t)cf & M62; cf >>= 62;
    g[1] = (int64_t)cg & M62; cg >>= 62;

    cf -= (int128_t)u * f3 + (int128_t)v * g3;
    cg -= (int128_t)q * f3 + (int128_t)r * g3;

    f[2] = (int64_t)cf & M62; cf >>= 62;
    g[2] = (int64_t)cg & M62; cg >>= 62;

    cf -= (int128_t)u * f4 + (int128_t)v * g4;
    cg -= (int128_t)q * f4 + (int128_t)r * g4;

    f[3] = (int64_t)cf & M62; cf >>= 62;
    g[3] = (int64_t)cg & M62; cg >>= 62;

    f[4] = (int64_t)cf;
    g[4] = (int64_t)cg;
}

static void secp256k1_fe_update_fg_62_var(int len, int64_t *f, int64_t *g, const int64_t *t) {

    const int64_t M62 = (int64_t)(UINT64_MAX >> 2);
    const int64_t u = t[0], v = t[1], q = t[2], r = t[3];
    int64_t fi, gi;
    int128_t cf = 0, cg = 0;
    int i;

    VERIFY_CHECK(len > 0);

    fi = f[0];
    gi = g[0];

    cf -= (int128_t)u * fi + (int128_t)v * gi;
    cg -= (int128_t)q * fi + (int128_t)r * gi;

    VERIFY_CHECK(((int64_t)cf & M62) == 0); cf >>= 62;
    VERIFY_CHECK(((int64_t)cg & M62) == 0); cg >>= 62;

    for (i = 1; i < len; ++i) {

        fi = f[i];
        gi = g[i];

        cf -= (int128_t)u * fi + (int128_t)v * gi;
        cg -= (int128_t)q * fi + (int128_t)r * gi;

        f[i - 1] = (int64_t)cf & M62; cf >>= 62;
        g[i - 1] = (int64_t)cg & M62; cg >>= 62;
    }

    f[len - 1] = (int64_t)cf;
    g[len - 1] = (int64_t)cg;
}

static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a) {

    /* Modular inversion based on the paper "Fast constant-time gcd computation and
     * modular inversion" by Daniel J. Bernstein and Bo-Yin Yang. */

    int64_t t[4];
    int64_t d[5] = { 0, 0, 0, 0, 0 };
    int64_t e[5] = { 1, 0, 0, 0, 0 };
    int64_t f[5] = { 0x3FFFFFFEFFFFFC2FLL, 0x3FFFFFFFFFFFFFFFLL, 0x3FFFFFFFFFFFFFFFLL,
        0x3FFFFFFFFFFFFFFFLL, 0xFFLL };
    int64_t g[5];
    secp256k1_fe b0, b1;
    int i, sign;
    uint64_t eta;
#ifdef VERIFY
    int zero_in;
#endif

    b0 = *a;
    secp256k1_fe_normalize(&b0);
    secp256k1_fe_encode_62(g, &b0);

#ifdef VERIFY
    zero_in = secp256k1_fe_is_zero(&b0);
#endif

    /* The paper uses 'delta'; eta == -delta (a performance tweak).
     *
     * If the maximum bitlength of g is known to be less than 256, then eta can be set
     * initially to -(1 + (256 - maxlen(g))), and only (741 - (256 - maxlen(g))) total
     * divsteps are needed. */
    eta = -(uint64_t)1;

    for (i = 0; i < 12; ++i) {
        eta = secp256k1_fe_divsteps_62(eta, f[0], g[0], t);
        secp256k1_fe_update_de_62(d, e, t);
        secp256k1_fe_update_fg_62(f, g, t);
    }

    /* At this point sufficient iterations have been performed that g must have reached 0
     * and (if g was not originally 0) f must now equal +/- GCD of the initial f, g
     * values i.e. +/- 1, and d now contains +/- the modular inverse. */

    VERIFY_CHECK((g[0] | g[1] | g[2] | g[3] | g[4]) == 0);

    sign = (f[0] >> 1) & 1;

    secp256k1_fe_decode_62(&b0, d);

    secp256k1_fe_negate(&b1, &b0, 1);
    secp256k1_fe_cmov(&b0, &b1, sign);
    secp256k1_fe_normalize_weak(&b0);

#ifdef VERIFY
    VERIFY_CHECK(!secp256k1_fe_normalizes_to_zero(&b0) == !zero_in);
#endif

    *r = b0;
}

static void secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *a) {

#define IS_THIS_FASTER 1

    /* Modular inversion based on the paper "Fast constant-time gcd computation and
     * modular inversion" by Daniel J. Bernstein and Bo-Yin Yang. */

    int64_t t[4];
    int64_t d[5] = { 0, 0, 0, 0, 0 };
    int64_t e[5] = { 1, 0, 0, 0, 0 };
    int64_t f[5] = { 0x3FFFFFFEFFFFFC2FLL, 0x3FFFFFFFFFFFFFFFLL, 0x3FFFFFFFFFFFFFFFLL,
        0x3FFFFFFFFFFFFFFFLL, 0xFFLL };
    int64_t g[5];
    secp256k1_fe b;
    int i, sign;
    uint64_t eta;
#if IS_THIS_FASTER
    int j, len = 5;
    int64_t cond, fn, gn;
#endif
#ifdef VERIFY
    int zero_in;
#endif

    b = *a;
    secp256k1_fe_normalize(&b);
    secp256k1_fe_encode_62(g, &b);

#ifdef VERIFY
    zero_in = secp256k1_fe_is_zero(&b);
#endif

    /* The paper uses 'delta'; eta == -delta (a performance tweak).
     *
     * If g has leading zeros (w.r.t 256 bits), then eta can be set initially to
     * -(1 + clz(g)), and the worst-case divstep count would be only (741 - clz(g)). */
    eta = -(uint64_t)1;

    for (i = 0; i < 12; ++i) {
#if IS_THIS_FASTER
        eta = secp256k1_fe_divsteps_62_var(eta, f[0], g[0], t);
        secp256k1_fe_update_de_62(d, e, t);
        secp256k1_fe_update_fg_62_var(len, f, g, t);

        if (g[0] == 0) {
            cond = 0;
            for (j = 1; j < len; ++j) {
                cond |= g[j];
            } 
            if (cond == 0) {
                break;
            }
        }

        fn = f[len - 1];
        gn = g[len - 1];

        cond = ((int64_t)len - 2) >> 63;
        cond |= fn ^ (fn >> 63);
        cond |= gn ^ (gn >> 63);

        if (cond == 0)
        {
            f[len - 2] |= fn << 62;
            g[len - 2] |= gn << 62;
            --len;
        }
#else
        eta = secp256k1_fe_divsteps_62_var(eta, f[0], g[0], t);
        secp256k1_fe_update_de_62(d, e, t);
        secp256k1_fe_update_fg_62(f, g, t);

        if (g[0] == 0) {
            if ((g[1] | g[2] | g[3] | g[4]) == 0) {
                break;
            }
        }
#endif
    }

    VERIFY_CHECK(i < 12);

    /* At this point g is 0 and (if g was not originally 0) f must now equal +/- GCD of
     * the initial f, g values i.e. +/- 1, and d now contains +/- the modular inverse. */

    sign = (f[0] >> 1) & 1;

    secp256k1_fe_decode_62(&b, d);

    if (sign) {
        secp256k1_fe_negate(&b, &b, 1);
        secp256k1_fe_normalize_weak(&b);
    }

#ifdef VERIFY
    VERIFY_CHECK(!secp256k1_fe_normalizes_to_zero(&b) == !zero_in);
#endif

    *r = b;
}

#endif /* SECP256K1_FIELD_REPR_IMPL_H */
