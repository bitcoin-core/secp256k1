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

static const secp256k1_fe SECP256K1_FE_TWO_POW_744 = SECP256K1_FE_CONST(
    0x0E90A100UL, 0x00000000UL, 0x00000000UL, 0x00000000UL,
    0x00000000UL, 0x00000100UL, 0x000B7300UL, 0x1D214200UL
);

static void secp256k1_fe_mul_add(int64_t a0, int64_t a1, int64_t b0, int64_t b1, int64_t c0, int64_t c1, int64_t d0, int64_t d1, int64_t *t) {

    /*  Each [a0,a1], etc. pair is a 126-bit signed value e.g. a0 + a1 * 2^64.
     *  This method calculates ([a0,a1] * [c0,c1]) + ([b0,b1] * [d0,d1]), and
     *  writes the 252-bit signed result to [t[0],t[1],t[2],t[3]].
     */

    int64_t z0, z1, z2, z3;
    int128_t tt;

    tt  = (int128_t)a0 * b0
        + (int128_t)c0 * d0;
    z0  = (int64_t)tt; tt -= z0; tt >>= 64;

    tt += (int128_t)a0 * b1
        + (int128_t)a1 * b0
        + (int128_t)c0 * d1
        + (int128_t)c1 * d0;
    z1  = (int64_t)tt; tt -= z1; tt >>= 64;

    tt += (int128_t)a1 * b1
        + (int128_t)c1 * d1;
    z2  = (int64_t)tt; tt -= z2; tt >>= 64;

    z3 = (int64_t)tt;

    t[0] = z0; t[1] = z1; t[2] = z2; t[3] = z3;
}

static void secp256k1_fe_combine_1s(int64_t *t) {

    int64_t a = t[0], b = t[1], c = t[2], d = t[3],
            e = t[4], f = t[5], g = t[6], h = t[7];
    int128_t I, J, K, L;

    I = (int128_t)e * a + (int128_t)f * c;
    J = (int128_t)e * b + (int128_t)f * d;
    K = (int128_t)g * a + (int128_t)h * c;
    L = (int128_t)g * b + (int128_t)h * d;

    a = (int64_t)I; I -= a; I >>= 64; b = (int64_t)I;
    c = (int64_t)J; J -= c; J >>= 64; d = (int64_t)J;
    e = (int64_t)K; K -= e; K >>= 64; f = (int64_t)K;
    g = (int64_t)L; L -= g; L >>= 64; h = (int64_t)L;

    t[0] = a; t[1] = b; t[2] = c; t[3] = d;
    t[4] = e; t[5] = f; t[6] = g; t[7] = h;
}

static void secp256k1_fe_combine_2s(int64_t *t) {

    int64_t a0 = t[ 0], a1 = t[ 1];
    int64_t b0 = t[ 2], b1 = t[ 3];
    int64_t c0 = t[ 4], c1 = t[ 5];
    int64_t d0 = t[ 6], d1 = t[ 7];
    int64_t e0 = t[ 8], e1 = t[ 9];
    int64_t f0 = t[10], f1 = t[11];
    int64_t g0 = t[12], g1 = t[13];
    int64_t h0 = t[14], h1 = t[15];

    secp256k1_fe_mul_add(e0, e1, a0, a1, f0, f1, c0, c1, &t[0]);
    secp256k1_fe_mul_add(e0, e1, b0, b1, f0, f1, d0, d1, &t[4]);
    secp256k1_fe_mul_add(g0, g1, a0, a1, h0, h1, c0, c1, &t[8]);
    secp256k1_fe_mul_add(g0, g1, b0, b1, h0, h1, d0, d1, &t[12]);
}

static void secp256k1_fe_decode_matrix(secp256k1_fe *r, int64_t *t) {

    uint64_t u0, u1, u2, u3, u4;
    uint64_t r0, r1, r2, r3, r4;
    int128_t cc;

    cc  = t[0];
    u0  = (uint64_t)cc; cc >>= 64;
    cc += t[1];
    u1  = (uint64_t)cc; cc >>= 64;
    cc += t[2];
    u2  = (uint64_t)cc; cc >>= 64;
    cc += t[3];
    u3  = (uint64_t)cc; cc >>= 64;
    u4  = (uint64_t)cc;

    VERIFY_CHECK(u4 == 0 || u4 == UINT64_MAX);

    /* Add twice the field prime in case u4 is non-zero (which represents -2^256). */
    r0 = 0xFFFFEFFFFFC2FULL * 2;
    r1 = 0xFFFFFFFFFFFFFULL * 2;
    r2 = 0xFFFFFFFFFFFFFULL * 2;
    r3 = 0xFFFFFFFFFFFFFULL * 2;
    r4 = 0x0FFFFFFFFFFFFULL * 2;

    r0 += u0 & 0xFFFFFFFFFFFFFULL;
    r1 += u0 >> 52 | ((u1 << 12) & 0xFFFFFFFFFFFFFULL);
    r2 += u1 >> 40 | ((u2 << 24) & 0xFFFFFFFFFFFFFULL);
    r3 += u2 >> 28 | ((u3 << 36) & 0xFFFFFFFFFFFFFULL);
    r4 += u3 >> 16 |  (u4 << 48);

    r->n[0] = r0;
    r->n[1] = r1;
    r->n[2] = r2;
    r->n[3] = r3;
    r->n[4] = r4;

#ifdef VERIFY
    r->magnitude = 2;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_encode_62(int64_t *r, const secp256k1_fe *a) {

    const uint64_t M62 = UINT64_MAX >> 2;
    const uint64_t *n = &a->n[0];
    uint64_t a0 = n[0], a1 = n[1], a2 = n[2], a3 = n[3], a4 = n[4];

#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif

    r[0] = (a0       | a1 << 52) & M62;
    r[1] = (a1 >> 10 | a2 << 42) & M62;
    r[2] = (a2 >> 20 | a3 << 32) & M62;
    r[3] = (a3 >> 30 | a4 << 22) & M62;
    r[4] =  a4 >> 40;
}

static int secp256k1_fe_divsteps_62(uint16_t eta, uint64_t f, uint64_t g, int64_t *t) {

    uint64_t u = -(uint64_t)1, v = 0, q = 0, r = -(uint64_t)1;
    uint64_t c1, c2, x, y, z;
    int i;

    for (i = 0; i < 62; ++i) {

        c1 = -(g & (eta >> 15));

        x = (f ^ g) & c1;
        f ^= x; g ^= x; g ^= c1; g -= c1;

        y = (u ^ q) & c1;
        u ^= y; q ^= y; q ^= c1; q -= c1;

        z = (v ^ r) & c1;
        v ^= z; r ^= z; r ^= c1; r -= c1;

        eta = (eta ^ (uint16_t)c1) - (uint16_t)c1 - 1;

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

static void secp256k1_fe_update_fg(int len, int64_t *f, int64_t *g, int64_t *t) {

    const int64_t M62 = (int64_t)(UINT64_MAX >> 2);
    int64_t u = t[0], v = t[1], q = t[2], r = t[3], fi, gi;
    int128_t cf = 0, cg = 0;
    int i;

    VERIFY_CHECK(len > 0);

    fi = f[0];
    gi = g[0];

    cf -= (int128_t)u * fi + (int128_t)v * gi;
    cg -= (int128_t)q * fi + (int128_t)r * gi;

    VERIFY_CHECK(((int64_t)cf & M62) == 0);
    VERIFY_CHECK(((int64_t)cg & M62) == 0);

    cf >>= 62;
    cg >>= 62;

    for (i = 1; i < len; ++i) {

        fi = f[i];
        gi = g[i];

        cf -= (int128_t)u * fi + (int128_t)v * gi;
        cg -= (int128_t)q * fi + (int128_t)r * gi;

        f[i - 1] = (int64_t)cf & M62; cf >>= 62;
        g[i - 1] = (int64_t)cg & M62; cg >>= 62;
    }

    f[i - 1] = (int64_t)cf;
    g[i - 1] = (int64_t)cg;
}

static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a) {

#if 1

    /* TODO Check for a == 0? */

    int64_t t[12 * 4];
    int64_t f[5] = { 0x3FFFFFFEFFFFFC2FLL, 0x3FFFFFFFFFFFFFFFLL, 0x3FFFFFFFFFFFFFFFLL,
        0x3FFFFFFFFFFFFFFFLL, 0xFFLL };
    int64_t g[5];
    secp256k1_fe b0, d0, a1, b1, c1, d1;
    int i, len, sign;
    int16_t eta;

    /* TODO 2^256 (mod p) is small, so it could be faster to multiply the input
     * by 2^768, and then the output by 2^24. */
    /* Instead of dividing the output by 2^744, we scale the input. */
    secp256k1_fe_mul(&b0, a, &SECP256K1_FE_TWO_POW_744);
    secp256k1_fe_normalize(&b0);
    secp256k1_fe_encode_62(&g[0], &b0);

    eta = -1;

    for (i = 0; i < 12; ++i) {
        eta = secp256k1_fe_divsteps_62(eta, f[0], g[0], &t[i * 4]);
        len = i <= 6 ? 5 : i >= 10 ? 1 : 11 - i;
        secp256k1_fe_update_fg(len, f, g, &t[i * 4]);
    }

    /* At this point, f must equal +/- 1 (the GCD). */
    sign = (f[0] >> 1) & 1;

    for (i = 0; i < 3; ++i) {
        int tOff = i * 16;
        secp256k1_fe_combine_1s(&t[tOff + 0]);
        secp256k1_fe_combine_1s(&t[tOff + 8]);
        secp256k1_fe_combine_2s(&t[tOff + 0]);
    }

    /* secp256k1_fe_decode_matrix(&a0, &t[0]); */
    secp256k1_fe_decode_matrix(&b0, &t[4]);
    /* secp256k1_fe_decode_matrix(&c0, &t[8]); */
    secp256k1_fe_decode_matrix(&d0, &t[12]);

    secp256k1_fe_decode_matrix(&a1, &t[16]);
    secp256k1_fe_decode_matrix(&b1, &t[20]);
    secp256k1_fe_decode_matrix(&c1, &t[24]);
    secp256k1_fe_decode_matrix(&d1, &t[28]);

    secp256k1_fe_mul(&a1, &a1, &b0);
    secp256k1_fe_mul(&b1, &b1, &d0);
    secp256k1_fe_mul(&c1, &c1, &b0);
    secp256k1_fe_mul(&d1, &d1, &d0);

    b0 = a1; secp256k1_fe_add(&b0, &b1);
    d0 = c1; secp256k1_fe_add(&d0, &d1);

    secp256k1_fe_decode_matrix(&a1, &t[32]);
    secp256k1_fe_decode_matrix(&b1, &t[36]);
    /* secp256k1_fe_decode_matrix(&c1, &t[40]); */
    /* secp256k1_fe_decode_matrix(&d1, &t[44]); */

    secp256k1_fe_mul(&a1, &a1, &b0);
    secp256k1_fe_mul(&b1, &b1, &d0);
    /* secp256k1_fe_mul(&c1, &c1, &b0); */
    /* secp256k1_fe_mul(&d1, &d1, &d0); */

    b0 = a1; secp256k1_fe_add(&b0, &b1);
    /* d0 = c1; secp256k1_fe_add(&d0, &d1); */

    secp256k1_fe_negate(&b1, &b0, 2);
    secp256k1_fe_cmov(&b0, &b1, sign);
    secp256k1_fe_normalize_weak(&b0);

    *r = b0;

#else

    secp256k1_fe x2, x3, x6, x9, x11, x22, x44, x88, x176, x220, x223, t1;
    int j;

    /** The binary representation of (p - 2) has 5 blocks of 1s, with lengths in
     *  { 1, 2, 22, 223 }. Use an addition chain to calculate 2^n - 1 for each block:
     *  [1], [2], 3, 6, 9, 11, [22], 44, 88, 176, 220, [223]
     */

    secp256k1_fe_sqr(&x2, a);
    secp256k1_fe_mul(&x2, &x2, a);

    secp256k1_fe_sqr(&x3, &x2);
    secp256k1_fe_mul(&x3, &x3, a);

    x6 = x3;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x6, &x6);
    }
    secp256k1_fe_mul(&x6, &x6, &x3);

    x9 = x6;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x9, &x9);
    }
    secp256k1_fe_mul(&x9, &x9, &x3);

    x11 = x9;
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(&x11, &x11);
    }
    secp256k1_fe_mul(&x11, &x11, &x2);

    x22 = x11;
    for (j=0; j<11; j++) {
        secp256k1_fe_sqr(&x22, &x22);
    }
    secp256k1_fe_mul(&x22, &x22, &x11);

    x44 = x22;
    for (j=0; j<22; j++) {
        secp256k1_fe_sqr(&x44, &x44);
    }
    secp256k1_fe_mul(&x44, &x44, &x22);

    x88 = x44;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x88, &x88);
    }
    secp256k1_fe_mul(&x88, &x88, &x44);

    x176 = x88;
    for (j=0; j<88; j++) {
        secp256k1_fe_sqr(&x176, &x176);
    }
    secp256k1_fe_mul(&x176, &x176, &x88);

    x220 = x176;
    for (j=0; j<44; j++) {
        secp256k1_fe_sqr(&x220, &x220);
    }
    secp256k1_fe_mul(&x220, &x220, &x44);

    x223 = x220;
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&x223, &x223);
    }
    secp256k1_fe_mul(&x223, &x223, &x3);

    /* The final result is then assembled using a sliding window over the blocks. */

    t1 = x223;
    for (j=0; j<23; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x22);
    for (j=0; j<5; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, a);
    for (j=0; j<3; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(&t1, &t1, &x2);
    for (j=0; j<2; j++) {
        secp256k1_fe_sqr(&t1, &t1);
    }
    secp256k1_fe_mul(r, a, &t1);
#endif
}

#endif /* SECP256K1_FIELD_REPR_IMPL_H */
