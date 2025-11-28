/******************************************************************************
 * Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra, Jonas Nick  *
 * Distributed under the MIT software license, see the accompanying           *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.       *
 ******************************************************************************/

#ifndef SECP256K1_ECMULT_IMPL_H
#define SECP256K1_ECMULT_IMPL_H

#include <string.h>
#include <stdint.h>

#include "util.h"
#include "group.h"
#include "scalar.h"
#include "ecmult.h"
#include "precomputed_ecmult.h"

#if defined(EXHAUSTIVE_TEST_ORDER)
/* We need to lower these values for exhaustive tests because
 * the tables cannot have infinities in them (this breaks the
 * affine-isomorphism stuff which tracks z-ratios) */
#  if EXHAUSTIVE_TEST_ORDER > 128
#    define WINDOW_A 5
#  elif EXHAUSTIVE_TEST_ORDER > 8
#    define WINDOW_A 4
#  else
#    define WINDOW_A 2
#  endif
#else
/* optimal for 128-bit and 256-bit exponents. */
#  define WINDOW_A 5
/** Larger values for ECMULT_WINDOW_SIZE result in possibly better
 *  performance at the cost of an exponentially larger precomputed
 *  table. The exact table size is
 *      (1 << (WINDOW_G - 2)) * sizeof(secp256k1_ge_storage)  bytes,
 *  where sizeof(secp256k1_ge_storage) is typically 64 bytes but can
 *  be larger due to platform-specific padding and alignment.
 *  Two tables of this size are used (due to the endomorphism
 *  optimization).
 */
#endif

#define WNAF_BITS 128
#define WNAF_SIZE_BITS(bits, w) CEIL_DIV(bits, w)
#define WNAF_SIZE(w) WNAF_SIZE_BITS(WNAF_BITS, w)

#define PIPPENGER_MAX_BUCKET_WINDOW 12

#define ECMULT_MAX_POINTS_PER_BATCH 5000000

/** Fill a table 'pre_a' with precomputed odd multiples of a.
 *  pre_a will contain [1*a,3*a,...,(2*n-1)*a], so it needs space for n group elements.
 *  zr needs space for n field elements.
 *
 *  Although pre_a is an array of _ge rather than _gej, it actually represents elements
 *  in Jacobian coordinates with their z coordinates omitted. The omitted z-coordinates
 *  can be recovered using z and zr. Using the notation z(b) to represent the omitted
 *  z coordinate of b:
 *  - z(pre_a[n-1]) = 'z'
 *  - z(pre_a[i-1]) = z(pre_a[i]) / zr[i] for n > i > 0
 *
 *  Lastly the zr[0] value, which isn't used above, is set so that:
 *  - a.z = z(pre_a[0]) / zr[0]
 */
static void secp256k1_ecmult_odd_multiples_table(size_t n, secp256k1_ge *pre_a, secp256k1_fe *zr, secp256k1_fe *z, const secp256k1_gej *a) {
    secp256k1_gej d, ai;
    secp256k1_ge d_ge;
    size_t i;

    VERIFY_CHECK(!secp256k1_gej_is_infinity(a));

    secp256k1_gej_double_var(&d, a, NULL);

    /*
     * Perform the additions using an isomorphic curve Y^2 = X^3 + 7*C^6 where C := d.z.
     * The isomorphism, phi, maps a secp256k1 point (x, y) to the point (x*C^2, y*C^3) on the other curve.
     * In Jacobian coordinates phi maps (x, y, z) to (x*C^2, y*C^3, z) or, equivalently to (x, y, z/C).
     *
     *     phi(x, y, z) = (x*C^2, y*C^3, z) = (x, y, z/C)
     *   d_ge := phi(d) = (d.x, d.y, 1)
     *     ai := phi(a) = (a.x*C^2, a.y*C^3, a.z)
     *
     * The group addition functions work correctly on these isomorphic curves.
     * In particular phi(d) is easy to represent in affine coordinates under this isomorphism.
     * This lets us use the faster secp256k1_gej_add_ge_var group addition function that we wouldn't be able to use otherwise.
     */
    secp256k1_ge_set_xy(&d_ge, &d.x, &d.y);
    secp256k1_ge_set_gej_zinv(&pre_a[0], a, &d.z);
    secp256k1_gej_set_ge(&ai, &pre_a[0]);
    ai.z = a->z;

    /* pre_a[0] is the point (a.x*C^2, a.y*C^3, a.z*C) which is equivalent to a.
     * Set zr[0] to C, which is the ratio between the omitted z(pre_a[0]) value and a.z.
     */
    zr[0] = d.z;

    for (i = 1; i < n; i++) {
        secp256k1_gej_add_ge_var(&ai, &ai, &d_ge, &zr[i]);
        secp256k1_ge_set_xy(&pre_a[i], &ai.x, &ai.y);
    }

    /* Multiply the last z-coordinate by C to undo the isomorphism.
     * Since the z-coordinates of the pre_a values are implied by the zr array of z-coordinate ratios,
     * undoing the isomorphism here undoes the isomorphism for all pre_a values.
     */
    secp256k1_fe_mul(z, &ai.z, &d.z);
}

SECP256K1_INLINE static void secp256k1_ecmult_table_verify(int n, int w) {
    (void)n;
    (void)w;
    VERIFY_CHECK(((n) & 1) == 1);
    VERIFY_CHECK((n) >= -((1 << ((w)-1)) - 1));
    VERIFY_CHECK((n) <=  ((1 << ((w)-1)) - 1));
}

SECP256K1_INLINE static void secp256k1_ecmult_table_get_ge(secp256k1_ge *r, const secp256k1_ge *pre, int n, int w) {
    secp256k1_ecmult_table_verify(n,w);
    if (n > 0) {
        *r = pre[(n-1)/2];
    } else {
        *r = pre[(-n-1)/2];
        secp256k1_fe_negate(&(r->y), &(r->y), 1);
    }
}

SECP256K1_INLINE static void secp256k1_ecmult_table_get_ge_lambda(secp256k1_ge *r, const secp256k1_ge *pre, const secp256k1_fe *x, int n, int w) {
    secp256k1_ecmult_table_verify(n,w);
    if (n > 0) {
        secp256k1_ge_set_xy(r, &x[(n-1)/2], &pre[(n-1)/2].y);
    } else {
        secp256k1_ge_set_xy(r, &x[(-n-1)/2], &pre[(-n-1)/2].y);
        secp256k1_fe_negate(&(r->y), &(r->y), 1);
    }
}

SECP256K1_INLINE static void secp256k1_ecmult_table_get_ge_storage(secp256k1_ge *r, const secp256k1_ge_storage *pre, int n, int w) {
    secp256k1_ecmult_table_verify(n,w);
    if (n > 0) {
        secp256k1_ge_from_storage(r, &pre[(n-1)/2]);
    } else {
        secp256k1_ge_from_storage(r, &pre[(-n-1)/2]);
        secp256k1_fe_negate(&(r->y), &(r->y), 1);
    }
}

/** Convert a number to WNAF notation. The number becomes represented by sum(2^i * wnaf[i], i=0..bits),
 *  with the following guarantees:
 *  - each wnaf[i] is either 0, or an odd integer between -(1<<(w-1) - 1) and (1<<(w-1) - 1)
 *  - two non-zero entries in wnaf are separated by at least w-1 zeroes.
 *  - the number of set values in wnaf is returned. This number is at most 256, and at most one more
 *    than the number of bits in the (absolute value) of the input.
 */
static int secp256k1_ecmult_wnaf(int *wnaf, int len, const secp256k1_scalar *a, int w) {
    secp256k1_scalar s;
    int last_set_bit = -1;
    int bit = 0;
    int sign = 1;
    int carry = 0;

    VERIFY_CHECK(wnaf != NULL);
    VERIFY_CHECK(0 <= len && len <= 256);
    VERIFY_CHECK(a != NULL);
    VERIFY_CHECK(2 <= w && w <= 31);

    for (bit = 0; bit < len; bit++) {
        wnaf[bit] = 0;
    }

    s = *a;
    if (secp256k1_scalar_get_bits_limb32(&s, 255, 1)) {
        secp256k1_scalar_negate(&s, &s);
        sign = -1;
    }

    bit = 0;
    while (bit < len) {
        int now;
        int word;
        if (secp256k1_scalar_get_bits_limb32(&s, bit, 1) == (unsigned int)carry) {
            bit++;
            continue;
        }

        now = w;
        if (now > len - bit) {
            now = len - bit;
        }

        word = secp256k1_scalar_get_bits_var(&s, bit, now) + carry;

        carry = (word >> (w-1)) & 1;
        word -= carry << w;

        wnaf[bit] = sign * word;
        last_set_bit = bit;

        bit += now;
    }
#ifdef VERIFY
    {
        int verify_bit = bit;

        VERIFY_CHECK(carry == 0);

        while (verify_bit < 256) {
            VERIFY_CHECK(secp256k1_scalar_get_bits_limb32(&s, verify_bit, 1) == 0);
            verify_bit++;
        }
    }
#endif
    return last_set_bit + 1;
}

/* Same as secp256k1_ecmult_wnaf, but stores to int8_t array. Requires w <= 8. */
static int secp256k1_ecmult_wnaf_small(int8_t *wnaf, int len, const secp256k1_scalar *a, int w) {
    int wnaf_tmp[256];
    int ret, i;

    VERIFY_CHECK(2 <= w && w <= 8);
    ret = secp256k1_ecmult_wnaf(wnaf_tmp, len, a, w);

    for (i = 0; i < len; i++) {
        wnaf[i] = (int8_t)wnaf_tmp[i];
    }

    return ret;
}

struct secp256k1_strauss_point_state {
    int8_t wnaf_na_1[129];
    int8_t wnaf_na_lam[129];
    int bits_na_1;
    int bits_na_lam;
};

struct secp256k1_strauss_state {
    /* aux is used to hold z-ratios, and then used to hold pre_a[i].x * BETA values. */
    secp256k1_fe* aux;
    secp256k1_ge* pre_a;
    struct secp256k1_strauss_point_state* ps;
};

static void secp256k1_ecmult_strauss_wnaf(const struct secp256k1_strauss_state *state, secp256k1_gej *r, size_t num, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
    secp256k1_ge tmpa;
    secp256k1_fe Z;
    /* Split G factors. */
    secp256k1_scalar ng_1, ng_128;
    int wnaf_ng_1[129];
    int bits_ng_1 = 0;
    int wnaf_ng_128[129];
    int bits_ng_128 = 0;
    int i;
    int bits = 0;
    size_t np;
    size_t no = 0;

    secp256k1_fe_set_int(&Z, 1);
    for (np = 0; np < num; ++np) {
        secp256k1_gej tmp;
        secp256k1_scalar na_1, na_lam;
        if (secp256k1_scalar_is_zero(&na[np]) || secp256k1_gej_is_infinity(&a[np])) {
            continue;
        }
        /* split na into na_1 and na_lam (where na = na_1 + na_lam*lambda, and na_1 and na_lam are ~128 bit) */
        secp256k1_scalar_split_lambda(&na_1, &na_lam, &na[np]);

        /* build wnaf representation for na_1 and na_lam. */
        state->ps[no].bits_na_1   = secp256k1_ecmult_wnaf_small(state->ps[no].wnaf_na_1,   129, &na_1,   WINDOW_A);
        state->ps[no].bits_na_lam = secp256k1_ecmult_wnaf_small(state->ps[no].wnaf_na_lam, 129, &na_lam, WINDOW_A);
        VERIFY_CHECK(state->ps[no].bits_na_1 <= 129);
        VERIFY_CHECK(state->ps[no].bits_na_lam <= 129);
        if (state->ps[no].bits_na_1 > bits) {
            bits = state->ps[no].bits_na_1;
        }
        if (state->ps[no].bits_na_lam > bits) {
            bits = state->ps[no].bits_na_lam;
        }

        /* Calculate odd multiples of a.
         * All multiples are brought to the same Z 'denominator', which is stored
         * in Z. Due to secp256k1' isomorphism we can do all operations pretending
         * that the Z coordinate was 1, use affine addition formulae, and correct
         * the Z coordinate of the result once at the end.
         * The exception is the precomputed G table points, which are actually
         * affine. Compared to the base used for other points, they have a Z ratio
         * of 1/Z, so we can use secp256k1_gej_add_zinv_var, which uses the same
         * isomorphism to efficiently add with a known Z inverse.
         */
        tmp = a[np];
        if (no) {
            secp256k1_gej_rescale(&tmp, &Z);
        }
        secp256k1_ecmult_odd_multiples_table(ECMULT_TABLE_SIZE(WINDOW_A), state->pre_a + no * ECMULT_TABLE_SIZE(WINDOW_A), state->aux + no * ECMULT_TABLE_SIZE(WINDOW_A), &Z, &tmp);
        if (no) secp256k1_fe_mul(state->aux + no * ECMULT_TABLE_SIZE(WINDOW_A), state->aux + no * ECMULT_TABLE_SIZE(WINDOW_A), &(a[np].z));

        ++no;
    }

    /* Bring them to the same Z denominator. */
    if (no) {
        secp256k1_ge_table_set_globalz(ECMULT_TABLE_SIZE(WINDOW_A) * no, state->pre_a, state->aux);
    }

    for (np = 0; np < no; ++np) {
        size_t j;
        for (j = 0; j < ECMULT_TABLE_SIZE(WINDOW_A); j++) {
            secp256k1_fe_mul(&state->aux[np * ECMULT_TABLE_SIZE(WINDOW_A) + j], &state->pre_a[np * ECMULT_TABLE_SIZE(WINDOW_A) + j].x, &secp256k1_const_beta);
        }
    }

    if (ng) {
        /* split ng into ng_1 and ng_128 (where gn = gn_1 + gn_128*2^128, and gn_1 and gn_128 are ~128 bit) */
        secp256k1_scalar_split_128(&ng_1, &ng_128, ng);

        /* Build wnaf representation for ng_1 and ng_128 */
        bits_ng_1   = secp256k1_ecmult_wnaf(wnaf_ng_1,   129, &ng_1,   WINDOW_G);
        bits_ng_128 = secp256k1_ecmult_wnaf(wnaf_ng_128, 129, &ng_128, WINDOW_G);
        if (bits_ng_1 > bits) {
            bits = bits_ng_1;
        }
        if (bits_ng_128 > bits) {
            bits = bits_ng_128;
        }
    }

    secp256k1_gej_set_infinity(r);

    for (i = bits - 1; i >= 0; i--) {
        int n;
        secp256k1_gej_double_var(r, r, NULL);
        for (np = 0; np < no; ++np) {
            if (i < state->ps[np].bits_na_1 && (n = state->ps[np].wnaf_na_1[i])) {
                secp256k1_ecmult_table_get_ge(&tmpa, state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
                secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
            if (i < state->ps[np].bits_na_lam && (n = state->ps[np].wnaf_na_lam[i])) {
                secp256k1_ecmult_table_get_ge_lambda(&tmpa, state->pre_a + np * ECMULT_TABLE_SIZE(WINDOW_A), state->aux + np * ECMULT_TABLE_SIZE(WINDOW_A), n, WINDOW_A);
                secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
        }
        if (i < bits_ng_1 && (n = wnaf_ng_1[i])) {
            secp256k1_ecmult_table_get_ge_storage(&tmpa, secp256k1_pre_g, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
        if (i < bits_ng_128 && (n = wnaf_ng_128[i])) {
            secp256k1_ecmult_table_get_ge_storage(&tmpa, secp256k1_pre_g_128, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &Z);
        }
    }

    if (!secp256k1_gej_is_infinity(r)) {
        secp256k1_fe_mul(&r->z, &r->z, &Z);
    }
}

static void secp256k1_ecmult(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
    secp256k1_fe aux[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_ge pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    struct secp256k1_strauss_point_state ps[1];
    struct secp256k1_strauss_state state;

    state.aux = aux;
    state.pre_a = pre_a;
    state.ps = ps;
    secp256k1_ecmult_strauss_wnaf(&state, r, 1, a, na, ng);
}

/** Convert a number to WNAF notation.
 *  The number becomes represented by sum(2^{wi} * wnaf[i], i=0..WNAF_SIZE(w)+1) - return_val.
 *  It has the following guarantees:
 *  - each wnaf[i] is either 0 or an odd integer between -(1 << w) and (1 << w)
 *  - the number of words set is always WNAF_SIZE(w)
 *  - the returned skew is 0 or 1
 */
static int secp256k1_wnaf_fixed(int *wnaf, const secp256k1_scalar *s, int w) {
    int skew = 0;
    int pos;
    int max_pos;
    int last_w;
    const secp256k1_scalar *work = s;

    if (secp256k1_scalar_is_zero(s)) {
        for (pos = 0; pos < WNAF_SIZE(w); pos++) {
            wnaf[pos] = 0;
        }
        return 0;
    }

    if (secp256k1_scalar_is_even(s)) {
        skew = 1;
    }

    wnaf[0] = secp256k1_scalar_get_bits_var(work, 0, w) + skew;
    /* Compute last window size. Relevant when window size doesn't divide the
     * number of bits in the scalar */
    last_w = WNAF_BITS - (WNAF_SIZE(w) - 1) * w;

    /* Store the position of the first nonzero word in max_pos to allow
     * skipping leading zeros when calculating the wnaf. */
    for (pos = WNAF_SIZE(w) - 1; pos > 0; pos--) {
        int val = secp256k1_scalar_get_bits_var(work, pos * w, pos == WNAF_SIZE(w)-1 ? last_w : w);
        if(val != 0) {
            break;
        }
        wnaf[pos] = 0;
    }
    max_pos = pos;
    pos = 1;

    while (pos <= max_pos) {
        int val = secp256k1_scalar_get_bits_var(work, pos * w, pos == WNAF_SIZE(w)-1 ? last_w : w);
        if ((val & 1) == 0) {
            wnaf[pos - 1] -= (1 << w);
            wnaf[pos] = (val + 1);
        } else {
            wnaf[pos] = val;
        }
        /* Set a coefficient to zero if it is 1 or -1 and the proceeding digit
         * is strictly negative or strictly positive respectively. Only change
         * coefficients at previous positions because above code assumes that
         * wnaf[pos - 1] is odd.
         */
        if (pos >= 2 && ((wnaf[pos - 1] == 1 && wnaf[pos - 2] < 0) || (wnaf[pos - 1] == -1 && wnaf[pos - 2] > 0))) {
            if (wnaf[pos - 1] == 1) {
                wnaf[pos - 2] += 1 << w;
            } else {
                wnaf[pos - 2] -= 1 << w;
            }
            wnaf[pos - 1] = 0;
        }
        ++pos;
    }

    return skew;
}

struct secp256k1_pippenger_point_state {
    int skew_na;
    size_t input_pos;
};

struct secp256k1_pippenger_state {
    int *wnaf_na;
    struct secp256k1_pippenger_point_state* ps;
};

/*
 * pippenger_wnaf computes the result of a multi-point multiplication as
 * follows: The scalars are brought into wnaf with n_wnaf elements each. Then
 * for every i < n_wnaf, first each point is added to a "bucket" corresponding
 * to the point's wnaf[i]. Second, the buckets are added together such that
 * r += 1*bucket[0] + 3*bucket[1] + 5*bucket[2] + ...
 */
static int secp256k1_ecmult_pippenger_wnaf(secp256k1_gej *buckets, int bucket_window, struct secp256k1_pippenger_state *state, secp256k1_gej *r, const secp256k1_scalar *sc, const secp256k1_ge *pt, size_t num) {
    size_t n_wnaf = WNAF_SIZE(bucket_window+1);
    size_t np;
    size_t no = 0;
    int i;

    for (np = 0; np < num; ++np) {
        if (secp256k1_scalar_is_zero(&sc[np]) || secp256k1_ge_is_infinity(&pt[np])) {
            continue;
        }
        state->ps[no].input_pos = np;
        state->ps[no].skew_na = secp256k1_wnaf_fixed(&state->wnaf_na[no*n_wnaf], &sc[np], bucket_window+1);
        no++;
    }
    secp256k1_gej_set_infinity(r);

    if (no == 0) {
        return 1;
    }

    for (i = n_wnaf - 1; i >= 0; i--) {
        secp256k1_gej running_sum;
        int j;
        size_t buc;

        for (buc = 0; buc < ECMULT_TABLE_SIZE(bucket_window+2); buc++) {
            secp256k1_gej_set_infinity(&buckets[buc]);
        }

        for (np = 0; np < no; ++np) {
            int n = state->wnaf_na[np*n_wnaf + i];
            struct secp256k1_pippenger_point_state point_state = state->ps[np];
            secp256k1_ge tmp;

            if (i == 0) {
                /* correct for wnaf skew */
                int skew = point_state.skew_na;
                if (skew) {
                    secp256k1_ge_neg(&tmp, &pt[point_state.input_pos]);
                    secp256k1_gej_add_ge_var(&buckets[0], &buckets[0], &tmp, NULL);
                }
            }
            if (n > 0) {
                buc = (n - 1)/2;
                secp256k1_gej_add_ge_var(&buckets[buc], &buckets[buc], &pt[point_state.input_pos], NULL);
            } else if (n < 0) {
                buc = -(n + 1)/2;
                secp256k1_ge_neg(&tmp, &pt[point_state.input_pos]);
                secp256k1_gej_add_ge_var(&buckets[buc], &buckets[buc], &tmp, NULL);
            }
        }

        for (j = 0; j < bucket_window; j++) {
            secp256k1_gej_double_var(r, r, NULL);
        }

        secp256k1_gej_set_infinity(&running_sum);
        /* Accumulate the sum: bucket[0] + 3*bucket[1] + 5*bucket[2] + 7*bucket[3] + ...
         *                   = bucket[0] +   bucket[1] +   bucket[2] +   bucket[3] + ...
         *                   +         2 *  (bucket[1] + 2*bucket[2] + 3*bucket[3] + ...)
         * using an intermediate running sum:
         * running_sum = bucket[0] +   bucket[1] +   bucket[2] + ...
         *
         * The doubling is done implicitly by deferring the final window doubling (of 'r').
         */
        for (buc = ECMULT_TABLE_SIZE(bucket_window+2) - 1; buc > 0; buc--) {
            secp256k1_gej_add_var(&running_sum, &running_sum, &buckets[buc], NULL);
            secp256k1_gej_add_var(r, r, &running_sum, NULL);
        }

        secp256k1_gej_add_var(&running_sum, &running_sum, &buckets[0], NULL);
        secp256k1_gej_double_var(r, r, NULL);
        secp256k1_gej_add_var(r, r, &running_sum, NULL);
    }
    return 1;
}

SECP256K1_INLINE static void secp256k1_ecmult_endo_split(secp256k1_scalar *s1, secp256k1_scalar *s2, secp256k1_ge *p1, secp256k1_ge *p2) {
    secp256k1_scalar tmp = *s1;
    secp256k1_scalar_split_lambda(s1, s2, &tmp);
    secp256k1_ge_mul_lambda(p2, p1);

    if (secp256k1_scalar_is_high(s1)) {
        secp256k1_scalar_negate(s1, s1);
        secp256k1_ge_neg(p1, p1);
    }
    if (secp256k1_scalar_is_high(s2)) {
        secp256k1_scalar_negate(s2, s2);
        secp256k1_ge_neg(p2, p2);
    }
}

/**
 * Algorithm Selection: ABCD Model
 *
 * For each possible batch algorithm choice, memory usage is
 * m(x) = A*x + B and running time is
 * c(x) = C*x + D, where x is the batch size.
 *
 * A = per-point memory (bytes)
 * B = fixed memory overhead (bytes)
 * C = per-point time cost
 * D = fixed time overhead
 */

struct secp256k1_ecmult_multi_abcd {
    size_t A;
    size_t B;
    size_t C;
    size_t D;
};

/* Strauss per-point memory */
#define SECP256K1_STRAUSS_POINT_SIZE \
    ((sizeof(secp256k1_ge) + sizeof(secp256k1_fe)) * ECMULT_TABLE_SIZE(WINDOW_A) \
     + sizeof(struct secp256k1_strauss_point_state) \
     + sizeof(secp256k1_gej) + sizeof(secp256k1_scalar))

/* Pippenger per-entry memory */
#define SECP256K1_PIPPENGER_ENTRY_SIZE(w) \
    (sizeof(secp256k1_ge) + sizeof(secp256k1_scalar) \
     + sizeof(struct secp256k1_pippenger_point_state) \
     + WNAF_SIZE((w)+1) * sizeof(int))

/* Pippenger per-point memory: 2 entries due to endomorphism */
#define SECP256K1_PIPPENGER_POINT_SIZE(w) (2 * SECP256K1_PIPPENGER_ENTRY_SIZE(w))

/* Pippenger fixed overhead: buckets + state + 2 extra entries */
#define SECP256K1_PIPPENGER_FIXED_SIZE(w) \
    ((sizeof(secp256k1_gej) << (w)) \
     + 2 * SECP256K1_PIPPENGER_ENTRY_SIZE(w))

/*
 * ABCD constants for all batch algorithms.
 *
 * Index 0    = TRIVIAL (no memory, very slow)
 * Index 1    = STRAUSS (efficient for small batche sizes)
 * Index 2-13 = PIPPENGER with window sizes 1-12
 */
 static const struct secp256k1_ecmult_multi_abcd secp256k1_ecmult_multi_abcds[SECP256K1_ECMULT_MULTI_NUM_ALGOS] = {
/*  A (per-point bytes)                  B (fixed bytes)                     C      D     */
    {0,                                  0,                                  1000,  0     },
    {SECP256K1_STRAUSS_POINT_SIZE,       0,                                  109,   120   },
    {SECP256K1_PIPPENGER_POINT_SIZE(1),  SECP256K1_PIPPENGER_FIXED_SIZE(1),  197,   403   },
    {SECP256K1_PIPPENGER_POINT_SIZE(2),  SECP256K1_PIPPENGER_FIXED_SIZE(2),  148,   590   },
    {SECP256K1_PIPPENGER_POINT_SIZE(3),  SECP256K1_PIPPENGER_FIXED_SIZE(3),  117,   877   },
    {SECP256K1_PIPPENGER_POINT_SIZE(4),  SECP256K1_PIPPENGER_FIXED_SIZE(4),  100,   1340  },
    {SECP256K1_PIPPENGER_POINT_SIZE(5),  SECP256K1_PIPPENGER_FIXED_SIZE(5),  86,    2187  },
    {SECP256K1_PIPPENGER_POINT_SIZE(6),  SECP256K1_PIPPENGER_FIXED_SIZE(6),  75,    3703  },
    {SECP256K1_PIPPENGER_POINT_SIZE(7),  SECP256K1_PIPPENGER_FIXED_SIZE(7),  66,    6324  },
    {SECP256K1_PIPPENGER_POINT_SIZE(8),  SECP256K1_PIPPENGER_FIXED_SIZE(8),  61,    10681 },
    {SECP256K1_PIPPENGER_POINT_SIZE(9),  SECP256K1_PIPPENGER_FIXED_SIZE(9),  56,    19223 },
    {SECP256K1_PIPPENGER_POINT_SIZE(10), SECP256K1_PIPPENGER_FIXED_SIZE(10), 53,    36521 },
    {SECP256K1_PIPPENGER_POINT_SIZE(11), SECP256K1_PIPPENGER_FIXED_SIZE(11), 49,    71369 },
    {SECP256K1_PIPPENGER_POINT_SIZE(12), SECP256K1_PIPPENGER_FIXED_SIZE(12), 46,    130576},
};

static size_t secp256k1_ecmult_multi_batch_size(size_t mem_limit) {
    /* We are implicitly using the TRIVIAL algorithm as a fallback
     * but we will only use it if no other algorithm fits. If that
     * is the case we can use max points as the batch size. */
    size_t best_batch_size = ECMULT_MAX_POINTS_PER_BATCH;
    size_t min_optime = SIZE_MAX;
    int i;

    for (i = 1 /* ignores TRIVIAL */; i < SECP256K1_ECMULT_MULTI_NUM_ALGOS; i++) {
        const struct secp256k1_ecmult_multi_abcd *p = &secp256k1_ecmult_multi_abcds[i];
        size_t A = p->A, B = p->B, C = p->C, D = p->D, optime, batch_size;

        if (mem_limit <= B) continue;

        batch_size = (mem_limit - B) / A;

        if (batch_size == 0) continue;

        optime = C + D / batch_size;

        if (optime < min_optime) {
            min_optime = optime;
            best_batch_size = batch_size;
        }
    }

    return best_batch_size;
}

static secp256k1_ecmult_multi_algo secp256k1_ecmult_multi_select(size_t mem_limit, size_t batch_size) {
    secp256k1_ecmult_multi_algo best_algo = SECP256K1_ECMULT_MULTI_ALGO_TRIVIAL;
    size_t min_optime = SIZE_MAX;
    int i;

    /* Use TRIVIAL fallback */
    if (batch_size == 0) return best_algo;

    for (i = 0; i < SECP256K1_ECMULT_MULTI_NUM_ALGOS; i++) {
        const struct secp256k1_ecmult_multi_abcd *p = &secp256k1_ecmult_multi_abcds[i];
        size_t A = p->A, B = p->B, C = p->C, D = p->D, optime;
        size_t mem_usage = A * batch_size + B;

        if (mem_usage > mem_limit) continue;

        optime = C + D / batch_size;

        if (optime < min_optime) {
            min_optime = optime;
            best_algo = (secp256k1_ecmult_multi_algo)i;
        }
    }

    return best_algo;
}

/* Trivial algorithm: Computes ecmult_multi by simply multiplying and adding each point. */
static int secp256k1_ecmult_multi_trivial(
    secp256k1_gej *r,
    size_t n,
    const secp256k1_ge *points,
    const secp256k1_scalar *scalars,
    const secp256k1_scalar *scalar_g
) {
    size_t i;
    secp256k1_gej tmpj;

    secp256k1_gej_set_infinity(r);

    if (scalar_g != NULL) {
        secp256k1_gej_set_infinity(&tmpj);
        secp256k1_ecmult(r, &tmpj, &secp256k1_scalar_zero, scalar_g);
    }

    for (i = 0; i < n; i++) {
        secp256k1_gej pointj;
        if (secp256k1_ge_is_infinity(&points[i])) {
            continue;
        }
        secp256k1_gej_set_ge(&pointj, &points[i]);
        secp256k1_ecmult(&tmpj, &pointj, &scalars[i], NULL);
        secp256k1_gej_add_var(r, r, &tmpj, NULL);
    }

    return 1;
}

static int secp256k1_ecmult_multi_strauss(
    const secp256k1_callback *error_callback,
    secp256k1_gej *r,
    size_t n,
    const secp256k1_ge *points,
    const secp256k1_scalar *scalars,
    const secp256k1_scalar *scalar_g
) {
    struct secp256k1_strauss_state state;
    secp256k1_gej *points_gej = NULL;
    size_t i;
    int ret = 0;

    state.aux = NULL;
    state.pre_a = NULL;
    state.ps = NULL;

    secp256k1_gej_set_infinity(r);

    if (scalar_g == NULL && n == 0) {
        return 1;
    }

    if (n > 0) {
        state.aux = (secp256k1_fe *)checked_malloc(error_callback,
            n * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_fe));
        state.pre_a = (secp256k1_ge *)checked_malloc(error_callback,
            n * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_ge));
        state.ps = (struct secp256k1_strauss_point_state *)checked_malloc(error_callback,
            n * sizeof(struct secp256k1_strauss_point_state));
        points_gej = (secp256k1_gej *)checked_malloc(error_callback,
            n * sizeof(secp256k1_gej));

        if (state.aux == NULL || state.pre_a == NULL || state.ps == NULL ||
            points_gej == NULL) {
            goto cleanup;
        }

        for (i = 0; i < n; i++) {
            secp256k1_gej_set_ge(&points_gej[i], &points[i]);
        }
    }

    secp256k1_ecmult_strauss_wnaf(&state, r, n, points_gej, scalars, scalar_g);
    ret = 1;

cleanup:
    free(state.aux);
    free(state.pre_a);
    free(state.ps);
    free(points_gej);

    return ret;
}

/* Pippenger algorithm per window size */
static int secp256k1_ecmult_multi_pippenger(
    const secp256k1_callback *error_callback,
    secp256k1_gej *r,
    size_t n,
    const secp256k1_ge *points,
    const secp256k1_scalar *scalars,
    const secp256k1_scalar *scalar_g,
    int window_size
) {
    size_t entries = 2 * n + 2;
    size_t n_wnaf = WNAF_SIZE(window_size + 1);
    secp256k1_ge *points_endo = NULL;
    secp256k1_scalar *scalars_endo = NULL;
    secp256k1_gej *buckets = NULL;
    struct secp256k1_pippenger_state state_space;
    size_t idx = 0;
    size_t i;
    int ret = 0;

    state_space.ps = NULL;
    state_space.wnaf_na = NULL;

    secp256k1_gej_set_infinity(r);

    if (scalar_g == NULL && n == 0) {
        return 1;
    }

    if (window_size < 1) window_size = 1;
    if (window_size > PIPPENGER_MAX_BUCKET_WINDOW) window_size = PIPPENGER_MAX_BUCKET_WINDOW;

    points_endo = (secp256k1_ge *)checked_malloc(error_callback,
        entries * sizeof(secp256k1_ge));
    scalars_endo = (secp256k1_scalar *)checked_malloc(error_callback,
        entries * sizeof(secp256k1_scalar));
    state_space.ps = (struct secp256k1_pippenger_point_state *)checked_malloc(error_callback,
        entries * sizeof(struct secp256k1_pippenger_point_state));
    state_space.wnaf_na = (int *)checked_malloc(error_callback,
        entries * n_wnaf * sizeof(int));
    buckets = (secp256k1_gej *)checked_malloc(error_callback,
        ((size_t)1 << window_size) * sizeof(secp256k1_gej));

    if (points_endo == NULL || scalars_endo == NULL ||
        state_space.ps == NULL || state_space.wnaf_na == NULL || buckets == NULL) {
        goto cleanup;
    }

    if (scalar_g != NULL) {
        scalars_endo[0] = *scalar_g;
        points_endo[0] = secp256k1_ge_const_g;
        idx++;
        secp256k1_ecmult_endo_split(&scalars_endo[0], &scalars_endo[1],
                                     &points_endo[0], &points_endo[1]);
        idx++;
    }

    for (i = 0; i < n; i++) {
        if (secp256k1_ge_is_infinity(&points[i])) {
            continue;
        }
        scalars_endo[idx] = scalars[i];
        points_endo[idx] = points[i];
        idx++;
        secp256k1_ecmult_endo_split(&scalars_endo[idx - 1], &scalars_endo[idx],
                                     &points_endo[idx - 1], &points_endo[idx]);
        idx++;
    }

    secp256k1_ecmult_pippenger_wnaf(buckets, window_size, &state_space, r,
                                     scalars_endo, points_endo, idx);

    ret = 1;

cleanup:
    free(points_endo);
    free(scalars_endo);
    free(state_space.ps);
    free(state_space.wnaf_na);
    free(buckets);

    return ret;
}

static int secp256k1_ecmult_multi(
    const secp256k1_callback *error_callback,
    secp256k1_gej *r,
    size_t n_points,
    const secp256k1_ge *points,
    const secp256k1_scalar *scalars,
    const secp256k1_scalar *scalar_g,
    size_t mem_limit
) {
    secp256k1_ecmult_multi_algo algo = secp256k1_ecmult_multi_select(mem_limit, n_points);
    return secp256k1_ecmult_multi_internal(error_callback, algo, r, n_points, points, scalars, scalar_g);
}


static int secp256k1_ecmult_multi_internal(
    const secp256k1_callback *error_callback,
    secp256k1_ecmult_multi_algo algo,
    secp256k1_gej *r,
    size_t n_points,
    const secp256k1_ge *points,
    const secp256k1_scalar *scalars,
    const secp256k1_scalar *scalar_g
) {
    switch (algo) {
        case SECP256K1_ECMULT_MULTI_ALGO_TRIVIAL:
            return secp256k1_ecmult_multi_trivial(r, n_points, points, scalars, scalar_g);

        case SECP256K1_ECMULT_MULTI_ALGO_STRAUSS:
            return secp256k1_ecmult_multi_strauss(error_callback, r, n_points,
                                                  points, scalars, scalar_g);

        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_1:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 1);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_2:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 2);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_3:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 3);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_4:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 4);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_5:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 5);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_6:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 6);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_7:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 7);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_8:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 8);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_9:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 9);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_10:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 10);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_11:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 11);
        case SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_12:
            return secp256k1_ecmult_multi_pippenger(error_callback, r, n_points,
                                                    points, scalars, scalar_g, 12);
        default:
            return secp256k1_ecmult_multi_trivial(r, n_points, points, scalars, scalar_g);
    }
}

#endif /* SECP256K1_ECMULT_IMPL_H */
