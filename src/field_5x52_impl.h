/***********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FIELD_REPR_IMPL_H
#define SECP256K1_FIELD_REPR_IMPL_H

#ifdef X86
# include <immintrin.h>
#endif

#include "checkmem.h"
#include "util.h"
#include "field.h"
#include "modinv64_impl.h"

#include "field_5x52_int128_impl.h"

#ifdef VERIFY
static void secp256k1_fe_impl_verify(const secp256k1_fe *a) {
    const uint64_t *d = a->n;
    int m = a->normalized ? 1 : 2 * a->magnitude;
   /* secp256k1 'p' value defined in "Standards for Efficient Cryptography" (SEC2) 2.7.1. */
    VERIFY_CHECK(d[0] <= 0xFFFFFFFFFFFFFULL * m);
    VERIFY_CHECK(d[1] <= 0xFFFFFFFFFFFFFULL * m);
    VERIFY_CHECK(d[2] <= 0xFFFFFFFFFFFFFULL * m);
    VERIFY_CHECK(d[3] <= 0xFFFFFFFFFFFFFULL * m);
    VERIFY_CHECK(d[4] <= 0x0FFFFFFFFFFFFULL * m);
    if (a->normalized) {
        if ((d[4] == 0x0FFFFFFFFFFFFULL) && ((d[3] & d[2] & d[1]) == 0xFFFFFFFFFFFFFULL)) {
            VERIFY_CHECK(d[0] < 0xFFFFEFFFFFC2FULL);
        }
    }
}
#endif

static void secp256k1_fe_impl_get_bounds(secp256k1_fe *r, int m) {
    uint64_t two_m = 2 * m;
    uint64_t bound1 = 0xFFFFFFFFFFFFFULL * two_m;
    uint64_t bound2 = 0x0FFFFFFFFFFFFULL * two_m;
#ifdef __AVX2__
    __m256i vec = _mm256_set1_epi64x(bound1);
    _mm256_storeu_si256((__m256i *)r->n, vec);
#else
    r->n[0] = bound1;
    r->n[1] = bound1;
    r->n[2] = bound1;
    r->n[3] = bound1;
#endif
    r->n[4] = bound2;
}

static void secp256k1_fe_impl_normalize(secp256k1_fe *r) {
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
}

static void secp256k1_fe_impl_normalize_weak(secp256k1_fe *r) {
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
}

static void secp256k1_fe_impl_normalize_var(secp256k1_fe *r) {
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
}

static int secp256k1_fe_impl_normalizes_to_zero(const secp256k1_fe *r) {
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

static int secp256k1_fe_impl_normalizes_to_zero_var(const secp256k1_fe *r) {
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

SECP256K1_INLINE static void secp256k1_fe_impl_set_int(secp256k1_fe *r, int a) {
    r->n[0] = a;
#ifdef __AVX2__
    {
        const __m256i zeros = _mm256_setzero_si256(); /* TODO: precompute */
        _mm256_storeu_si256((__m256i *)(r->n + 1), zeros);
    }
#else
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
#endif
}

SECP256K1_INLINE static int secp256k1_fe_impl_is_zero(const secp256k1_fe *a) {
    const uint64_t *t = a->n;
    return (t[0] | t[1] | t[2] | t[3] | t[4]) == 0;
}

SECP256K1_INLINE static int secp256k1_fe_impl_is_odd(const secp256k1_fe *a) {
    return a->n[0] & 1;
}

static int secp256k1_fe_impl_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    int8_t diff;
    int i;
    for (i = 4; i >= 0; i--) {
        diff = (a->n[i] > b->n[i]) - (a->n[i] < b->n[i]);
        if (diff != 0) {
            return diff;
        }
    }
    return 0;
}

static void secp256k1_fe_impl_set_b32_mod(secp256k1_fe *r, const unsigned char *a) {
#ifdef __AVX2__
    __m256i vec = _mm256_loadu_si256((__m256i *)a);

    const __m256i bswap_mask = _mm256_setr_epi8( /* TODO: precompute */
        7, 6, 5, 4, 3, 2, 1, 0,
        15, 14, 13, 12, 11, 10, 9, 8,
        23, 22, 21, 20, 19, 18, 17, 16,
        31, 30, 29, 28, 27, 26, 25, 24
    );
    __m256i limbs_0123 = _mm256_shuffle_epi8(vec, bswap_mask);

    const __m256i masks = _mm256_setr_epi64x(0xFFFFFFFFFFFFFULL, 0xFFFFFFFFFFULL, 0xFFFFFFFULL, 0xFFFFULL);
    const __m256i shift_lhs = _mm256_setr_epi64x(64, 52, 40, 28); /* TODO: precompute */
    const __m256i shift_rhs = _mm256_setr_epi64x(0, 12, 24, 36); /* TODO: precompute */
    __m256i limbs_3210 = _mm256_permute4x64_epi64(limbs_0123, _MM_SHUFFLE(0, 1, 2, 3));
    __m256i limbs_3321 = _mm256_permute4x64_epi64(limbs_0123, _MM_SHUFFLE(1, 2, 3, 3));
    __m256i rhs = _mm256_sllv_epi64(_mm256_and_si256(limbs_3210, masks), shift_rhs);
    __m256i lhs = _mm256_srlv_epi64(limbs_3321, shift_lhs);
    __m256i out = _mm256_or_si256(lhs, rhs);
    _mm256_storeu_si256((__m256i *)r->n, out);

    r->n[4] = (_mm256_extract_epi64(limbs_0123, 0) >> 16) & 0xFFFFFFFFFFFFULL;
#else
    uint64_t limbs[4];
    memcpy(limbs, a, 32);

#ifdef LITTLE_ENDIAN
    limbs[0] = BYTESWAP_64(limbs[0]);
    limbs[1] = BYTESWAP_64(limbs[1]);
    limbs[2] = BYTESWAP_64(limbs[2]);
    limbs[3] = BYTESWAP_64(limbs[3]);
#endif

    r->n[0] =                     (limbs[3] & 0xFFFFFFFFFFFFFULL);
    r->n[1] = (limbs[3] >> 52) | ((limbs[2] & 0xFFFFFFFFFFULL) << 12);
    r->n[2] = (limbs[2] >> 40) | ((limbs[1] & 0xFFFFFFFULL) << 24);
    r->n[3] = (limbs[1] >> 28) | ((limbs[0] & 0xFFFFULL) << 36);

    r->n[4] = (limbs[0] >> 16) & 0xFFFFFFFFFFFFULL;
#endif
}

static int secp256k1_fe_impl_set_b32_limit(secp256k1_fe *r, const unsigned char *a) {
    secp256k1_fe_impl_set_b32_mod(r, a);
    return !((r->n[4] == 0x0FFFFFFFFFFFFULL) & ((r->n[3] & r->n[2] & r->n[1]) == 0xFFFFFFFFFFFFFULL) & (r->n[0] >= 0xFFFFEFFFFFC2FULL));
}

/** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
static void secp256k1_fe_impl_get_b32(unsigned char *r, const secp256k1_fe *a) {
    uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4];

#ifdef __AVX512F__
    const __m256i shifts1 = _mm256_setr_epi64x(40, 32, 24, 16); /* TODO: precompute */
    const __m256i shifts2 = _mm256_setr_epi64x(44, 36, 28, 20);/* TODO: precompute */
    /* load them all here because of load latency. load them in this order because of load latency */
    __m256i limb4 = _mm256_set1_epi64x(a4);
    __m256i limb3 = _mm256_set1_epi64x(a3);
    __m256i limb2 = _mm256_set1_epi64x(a2);
    __m256i limb1 = _mm256_set1_epi64x(a1);
    __m256i limb0 = _mm256_set1_epi64x(a0);
#endif

#ifdef __AVX512F__
    __m256i shifted = _mm256_srlv_epi64(limb4, shifts1);
    __m128i packed = _mm256_cvtepi64_epi8(shifted);
    uint32_t four_bytes = _mm_cvtsi128_si32(packed);
    memcpy(r, &four_bytes, 4);
#else
    r[0] = (a4 >> 40) & 0xFF;
    r[1] = (a4 >> 32) & 0xFF;
    r[2] = (a4 >> 24) & 0xFF;
    r[3] = (a4 >> 16) & 0xFF;
#endif
    r[4] = (a4 >> 8) & 0xFF;
    r[5] = a4 & 0xFF;
#ifdef __AVX512F__
    shifted = _mm256_srlv_epi64(limb3, shifts2);
    packed = _mm256_cvtepi64_epi8(shifted);
    four_bytes = _mm_cvtsi128_si32(packed);
    memcpy(r + 6, &four_bytes, 4);
#else
    r[6] = (a3 >> 44) & 0xFF;
    r[7] = (a3 >> 36) & 0xFF;
    r[8] = (a3 >> 28) & 0xFF;
    r[9] = (a3 >> 20) & 0xFF;
#endif
    r[10] = (a3 >> 12) & 0xFF;
    r[11] = (a3 >> 4) & 0xFF;
    r[12] = ((a2 >> 48) & 0xF) | ((a3 & 0xF) << 4);
#ifdef __AVX512F__
    shifted = _mm256_srlv_epi64(limb2, shifts1);
    packed = _mm256_cvtepi64_epi8(shifted);
    four_bytes = _mm_cvtsi128_si32(packed);
    memcpy(r + 13, &four_bytes, 4);
#else
    r[13] = (a2 >> 40) & 0xFF;
    r[14] = (a2 >> 32) & 0xFF;
    r[15] = (a2 >> 24) & 0xFF;
    r[16] = (a2 >> 16) & 0xFF;
#endif
    r[17] = (a2 >> 8) & 0xFF;
    r[18] = a2 & 0xFF;
#ifdef __AVX512F__
    shifted = _mm256_srlv_epi64(limb1, shifts2);
    packed = _mm256_cvtepi64_epi8(shifted);
    four_bytes = _mm_cvtsi128_si32(packed);
    memcpy(r + 19, &four_bytes, 4);
#else
    r[19] = (a1 >> 44) & 0xFF;
    r[20] = (a1 >> 36) & 0xFF;
    r[21] = (a1 >> 28) & 0xFF;
    r[22] = (a1 >> 20) & 0xFF;
#endif
    r[23] = (a1 >> 12) & 0xFF;
    r[24] = (a1 >> 4) & 0xFF;
    r[25] = ((a0 >> 48) & 0xF) | ((a1 & 0xF) << 4);
#ifdef __AVX512F__
    shifted = _mm256_srlv_epi64(limb0, shifts1);
    packed = _mm256_cvtepi64_epi8(shifted);
    four_bytes = _mm_cvtsi128_si32(packed);
    memcpy(r + 26, &four_bytes, 4);
#else
    r[26] = (a0 >> 40) & 0xFF;
    r[27] = (a0 >> 32) & 0xFF;
    r[28] = (a0 >> 24) & 0xFF;
    r[29] = (a0 >> 16) & 0xFF;
#endif
    r[30] = (a0 >> 8) & 0xFF;
    r[31] = a0 & 0xFF;
}

SECP256K1_INLINE static void secp256k1_fe_impl_negate_unchecked(secp256k1_fe *r, const secp256k1_fe *a, int m) {
#ifdef __AVX2__
    /* load here to mitigate load latency */
    __m256i vec_a = _mm256_loadu_si256((__m256i *)a->n);
#endif
  
    uint32_t two_m1 = 2 * (m + 1);

    uint64_t bound1 = 0xFFFFEFFFFFC2FULL * two_m1;
    uint64_t bound2 = 0xFFFFFFFFFFFFFULL * two_m1;
    uint64_t bound3 = 0x0FFFFFFFFFFFFULL * two_m1;

    /* For all legal values of m (0..31), the following properties hold: */
    VERIFY_CHECK(bound1 >= 0xFFFFFFFFFFFFFULL * 2 * m);
    VERIFY_CHECK(bound2 >= 0xFFFFFFFFFFFFFULL * 2 * m);
    VERIFY_CHECK(bound3 >= 0x0FFFFFFFFFFFFULL * 2 * m);

    /* Due to the properties above, the left hand in the subtractions below is never less than
     * the right hand. */
#ifdef __AVX2__
    {
        __m256i vec_bounds = _mm256_setr_epi64x(bound1, bound2, bound2, bound2);
        __m256i out = _mm256_sub_epi64(vec_bounds, vec_a);
        _mm256_storeu_si256((__m256i *)r->n, out);
    }
#else
    r->n[0] = bound1 - a->n[0];
    r->n[1] = bound2 - a->n[1];
    r->n[2] = bound2 - a->n[2];
    r->n[3] = bound2 - a->n[3];
#endif
    r->n[4] = bound3 - a->n[4];
}

SECP256K1_INLINE static void secp256k1_fe_impl_mul_int_unchecked(secp256k1_fe *r, int a) {
    r->n[0] *= a;
    r->n[1] *= a;
    r->n[2] *= a;
    r->n[3] *= a;
    r->n[4] *= a;
}

SECP256K1_INLINE static void secp256k1_fe_impl_add_int(secp256k1_fe *r, int a) {
    r->n[0] += a;
}

SECP256K1_INLINE static void secp256k1_fe_impl_add(secp256k1_fe *r, const secp256k1_fe *a) {
    r->n[0] += a->n[0];
    r->n[1] += a->n[1];
    r->n[2] += a->n[2];
    r->n[3] += a->n[3];
    r->n[4] += a->n[4];
}

SECP256K1_INLINE static void secp256k1_fe_impl_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) {
    secp256k1_fe_mul_inner(r->n, a->n, b->n);
}

SECP256K1_INLINE static void secp256k1_fe_impl_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
    secp256k1_fe_sqr_inner(r->n, a->n);
}

SECP256K1_INLINE static void secp256k1_fe_impl_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag) {
#ifdef __AVX2__
    /* load here to mitigate load latency */
    __m256i vec_r = _mm256_loadu_si256((__m256i *)(r->n + 1));
    __m256i vec_a = _mm256_loadu_si256((__m256i *)(a->n + 1));
#endif
  
    uint64_t mask0, mask1;
    volatile int vflag = flag;
    SECP256K1_CHECKMEM_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = vflag + ~((uint64_t)0);
    mask1 = ~mask0;

    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);

#ifdef __AVX2__
    {
        const __m256i vec_mask0 = _mm256_set1_epi64x(mask0); /* TODO: precompute*/
        const __m256i vec_mask1 = _mm256_set1_epi64x(mask1); /* TODO: precompute*/
        vec_r = _mm256_and_si256(vec_r, vec_mask0);
        vec_a = _mm256_and_si256(vec_a, vec_mask1);
        vec_r = _mm256_or_si256(vec_r, vec_a);
        _mm256_storeu_si256((__m256i *)(r->n + 1), vec_r);
    }
#else
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
#endif
}

static SECP256K1_INLINE void secp256k1_fe_impl_half(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];
    uint64_t one = (uint64_t)1;
    uint64_t mask = -(t0 & one) >> 12;

    /* Bounds analysis (over the rationals).
     *
     * Let m = r->magnitude
     *     C = 0xFFFFFFFFFFFFFULL * 2
     *     D = 0x0FFFFFFFFFFFFULL * 2
     *
     * Initial bounds: t0..t3 <= C * m
     *                     t4 <= D * m
     */

    t0 += 0xFFFFEFFFFFC2FULL & mask;
    t1 += mask;
    t2 += mask;
    t3 += mask;
    t4 += mask >> 4;

    VERIFY_CHECK((t0 & one) == 0);

    /* t0..t3: added <= C/2
     *     t4: added <= D/2
     *
     * Current bounds: t0..t3 <= C * (m + 1/2)
     *                     t4 <= D * (m + 1/2)
     */

#ifdef __AVX2__
    {
        __m256i limbs_0123 = _mm256_setr_epi64x(t0, t1, t2, t3);
        __m256i limbs_1234 = _mm256_setr_epi64x(t1, t2, t3, t4);
        const __m256i vec_one = _mm256_set1_epi64x(1); /* TODO: precompute */
        __m256i rhs = _mm256_slli_epi64(_mm256_and_si256(limbs_1234, vec_one), 51);
        __m256i lhs = _mm256_srli_epi64(limbs_0123, 1);
        __m256i out = _mm256_add_epi64(lhs, rhs);
        _mm256_storeu_si256((__m256i *)r->n, out);
    }
#else
    r->n[0] = (t0 >> 1) + ((t1 & one) << 51);
    r->n[1] = (t1 >> 1) + ((t2 & one) << 51);
    r->n[2] = (t2 >> 1) + ((t3 & one) << 51);
    r->n[3] = (t3 >> 1) + ((t4 & one) << 51);
#endif
    r->n[4] = (t4 >> 1);

    /* t0..t3: shifted right and added <= C/4 + 1/2
     *     t4: shifted right
     *
     * Current bounds: t0..t3 <= C * (m/2 + 1/2)
     *                     t4 <= D * (m/2 + 1/4)
     *
     * Therefore the output magnitude (M) has to be set such that:
     *     t0..t3: C * M >= C * (m/2 + 1/2)
     *         t4: D * M >= D * (m/2 + 1/4)
     *
     * It suffices for all limbs that, for any input magnitude m:
     *     M >= m/2 + 1/2
     *
     * and since we want the smallest such integer value for M:
     *     M == floor(m/2) + 1
     */
}

static SECP256K1_INLINE void secp256k1_fe_storage_cmov(secp256k1_fe_storage *r, const secp256k1_fe_storage *a, int flag) {
    uint64_t mask0, mask1;
    volatile int vflag = flag;
    SECP256K1_CHECKMEM_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = vflag + ~((uint64_t)0);
    mask1 = ~mask0;
#ifdef __AVX2__
    {
        const __m256i vec_mask0 = _mm256_set1_epi64x(mask0); /*TODO: precompute*/
        const __m256i vec_mask1 = _mm256_set1_epi64x(mask1); /*TODO: precompute*/
        __m256i vec_r = _mm256_loadu_si256((__m256i *)r->n);
        __m256i vec_a = _mm256_loadu_si256((__m256i *)a->n);
        vec_r = _mm256_and_si256(vec_r, vec_mask0);
        vec_a = _mm256_and_si256(vec_a, vec_mask1);
        vec_r = _mm256_or_si256(vec_r, vec_a);
        _mm256_storeu_si256((__m256i *)r->n, vec_r);
    }
#else
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
#endif
}

static void secp256k1_fe_impl_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a) {
#ifdef __AVX2__
    __m256i limbs_0123 = _mm256_loadu_si256((__m256i *)a->n);
    __m256i limbs_1234 = _mm256_loadu_si256((__m256i *)(a->n + 1));
    const __m256i shift_lhs = _mm256_setr_epi64x(0, 12, 24, 36); /* TODO: precompute */
    const __m256i shift_rhs = _mm256_setr_epi64x(52, 40, 28, 16); /* TODO: precompute */
    __m256i rhs = _mm256_sllv_epi64(limbs_1234, shift_rhs);
    __m256i lhs = _mm256_srlv_epi64(limbs_0123, shift_lhs);
    __m256i out = _mm256_or_si256(lhs, rhs);
    _mm256_storeu_si256((__m256i *)r->n, out);
#else
    r->n[0] = a->n[0]       | a->n[1] << 52;
    r->n[1] = a->n[1] >> 12 | a->n[2] << 40;
    r->n[2] = a->n[2] >> 24 | a->n[3] << 28;
    r->n[3] = a->n[3] >> 36 | a->n[4] << 16;
#endif
}

static SECP256K1_INLINE void secp256k1_fe_impl_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a) {
#ifdef __AVX2__
    {
        __m256i limbs_0123 = _mm256_loadu_si256((__m256i*)a->n);
        const __m256i shift_lhs = _mm256_setr_epi64x(64, 52, 40, 28); /* TODO: precompute */
        const __m256i shift_rhs = _mm256_setr_epi64x(0, 12, 24, 36); /* TODO: precompute */
        const __m256i mask52 = _mm256_set1_epi64x(0xFFFFFFFFFFFFFULL); /* TODO: precompute */
        __m256i limbs_0012 = _mm256_permute4x64_epi64(limbs_0123, _MM_SHUFFLE(2, 1, 0, 0));
        __m256i rhs = _mm256_and_si256(_mm256_sllv_epi64(limbs_0123, shift_rhs), mask52);
        __m256i lhs = _mm256_srlv_epi64(limbs_0012, shift_lhs);
        __m256i out = _mm256_or_si256(lhs, rhs);
        _mm256_storeu_si256((__m256i*)r->n, out);
    }
#else
    r->n[0] =                   a->n[0]        & 0xFFFFFFFFFFFFFULL;
    r->n[1] = a->n[0] >> 52 | ((a->n[1] << 12) & 0xFFFFFFFFFFFFFULL);
    r->n[2] = a->n[1] >> 40 | ((a->n[2] << 24) & 0xFFFFFFFFFFFFFULL);
    r->n[3] = a->n[2] >> 28 | ((a->n[3] << 36) & 0xFFFFFFFFFFFFFULL);
#endif
    r->n[4] = a->n[3] >> 16;
}

static void secp256k1_fe_from_signed62(secp256k1_fe *r, const secp256k1_modinv64_signed62 *a) {
    const uint64_t M52 = UINT64_MAX >> 12;
    uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];

    /* The output from secp256k1_modinv64{_var} should be normalized to range [0,modulus), and
     * have limbs in [0,2^62). The modulus is < 2^256, so the top limb must be below 2^(256-62*4).
     */
    VERIFY_CHECK(a0 >> 62 == 0);
    VERIFY_CHECK(a1 >> 62 == 0);
    VERIFY_CHECK(a2 >> 62 == 0);
    VERIFY_CHECK(a3 >> 62 == 0);
    VERIFY_CHECK(a4 >> 8 == 0);

#ifdef __AVX2__
    {
        __m256i limbs_0123 = _mm256_setr_epi64x(a0, a1, a2, a3);
        __m256i limbs_0012 = _mm256_setr_epi64x(a0, a0, a1, a2);
        const __m256i shift_lhs = _mm256_setr_epi64x(64, 52, 42, 32); /*TODO: precompute */
        const __m256i shift_rhs = _mm256_setr_epi64x(0, 10, 20, 30); /*TODO: precompute */
        const __m256i mask52 = _mm256_set1_epi64x(M52); /*TODO: precompute */
        __m256i rhs = _mm256_sllv_epi64(limbs_0123, shift_rhs);
        __m256i lhs = _mm256_srlv_epi64(limbs_0012, shift_lhs);
        __m256i out = _mm256_or_si256(lhs, rhs);
        out = _mm256_and_si256(out, mask52);
        _mm256_storeu_si256((__m256i*)r->n, out);
    }
#else
    r->n[0] =             a0        & M52;
    r->n[1] = (a0 >> 52 | a1 << 10) & M52;
    r->n[2] = (a1 >> 42 | a2 << 20) & M52;
    r->n[3] = (a2 >> 32 | a3 << 30) & M52;
#endif
    r->n[4] = (a3 >> 22 | a4 << 40);
}

static void secp256k1_fe_to_signed62(secp256k1_modinv64_signed62 *r, const secp256k1_fe *a) {
    const uint64_t M62 = UINT64_MAX >> 2;
    uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4];

#ifdef __AVX2__
    {
        __m256i limbs_0123 = _mm256_setr_epi64x(a0, a1, a2, a3);
        __m256i limbs_1234 = _mm256_setr_epi64x(a1, a2, a3, a4);
        const __m256i shift_lhs = _mm256_setr_epi64x(0, 10, 20, 30); /*TODO: precompute */
        const __m256i shift_rhs = _mm256_setr_epi64x(52, 42, 32, 22); /*TODO: precompute */
        const __m256i mask62 = _mm256_set1_epi64x(M62); /*TODO: precompute */
        __m256i lhs = _mm256_srlv_epi64(limbs_0123, shift_lhs);
        __m256i rhs = _mm256_sllv_epi64(limbs_1234, shift_rhs);
        __m256i out = _mm256_or_si256(lhs, rhs);
        out = _mm256_and_si256(out, mask62);
        _mm256_storeu_si256((__m256i *)r->v, out);
    }
#else
    r->v[0] = (a0       | a1 << 52) & M62;
    r->v[1] = (a1 >> 10 | a2 << 42) & M62;
    r->v[2] = (a2 >> 20 | a3 << 32) & M62;
    r->v[3] = (a3 >> 30 | a4 << 22) & M62;
#endif
    r->v[4] = a4 >> 40;
}

static const secp256k1_modinv64_modinfo secp256k1_const_modinfo_fe = {
    {{-0x1000003D1LL, 0, 0, 0, 256}},
    0x27C7F6E22DDACACFLL
};

static void secp256k1_fe_impl_inv(secp256k1_fe *r, const secp256k1_fe *x) {
    secp256k1_fe tmp = *x;
    secp256k1_modinv64_signed62 s;

    secp256k1_fe_normalize(&tmp);
    secp256k1_fe_to_signed62(&s, &tmp);
    secp256k1_modinv64(&s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed62(r, &s);
}

static void secp256k1_fe_impl_inv_var(secp256k1_fe *r, const secp256k1_fe *x) {
    secp256k1_fe tmp = *x;
    secp256k1_modinv64_signed62 s;

    secp256k1_fe_normalize_var(&tmp);
    secp256k1_fe_to_signed62(&s, &tmp);
    secp256k1_modinv64_var(&s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed62(r, &s);
}

static int secp256k1_fe_impl_is_square_var(const secp256k1_fe *x) {
    secp256k1_fe tmp;
    secp256k1_modinv64_signed62 s;
    int jac, ret;

    tmp = *x;
    secp256k1_fe_normalize_var(&tmp);
    /* secp256k1_jacobi64_maybe_var cannot deal with input 0. */
    if (secp256k1_fe_is_zero(&tmp)) return 1;
    secp256k1_fe_to_signed62(&s, &tmp);
    jac = secp256k1_jacobi64_maybe_var(&s, &secp256k1_const_modinfo_fe);
    if (jac == 0) {
        /* secp256k1_jacobi64_maybe_var failed to compute the Jacobi symbol. Fall back
         * to computing a square root. This should be extremely rare with random
         * input (except in VERIFY mode, where a lower iteration count is used). */
        secp256k1_fe dummy;
        ret = secp256k1_fe_sqrt(&dummy, &tmp);
    } else {
        ret = jac >= 0;
    }
    return ret;
}

#endif /* SECP256K1_FIELD_REPR_IMPL_H */
