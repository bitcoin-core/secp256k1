/**********************************************************************
 * Copyright (c) 2015 Pieter Wuille, Andrew Poelstra                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECDH_IMPL_
#define _SECP256K1_ECDH_IMPL_

#include "scalar.h"
#include "group.h"
#include "ecdh.h"
#include "ecmult_impl.h"

#ifdef USE_ENDOMORPHISM
    #define WNAF_BITS 128
#else
    #define WNAF_BITS 256
#endif
#define WNAF_SIZE(w) ((WNAF_BITS + (w) - 1) / (w))

/** Convert a number to WNAF notation. The number becomes represented by sum(2^{wi} * wnaf[i], i=0..return_val)
 *  with the following guarantees:
 *  - each wnaf[i] an odd integer between -(1 << w) and (1 << w)
 *  - each wnaf[i] is nonzero
 *  - the number of words set is returned; this is always (256 + w - 1) / w
 *
 *  Adapted from `The Width-w NAF Method Provides Small Memory and Fast Elliptic Scalar
 *  Multiplications Secure against Side Channel Attacks`, Okeya and Tagaki. M. Joye (Ed.)
 *  CT-RSA 2003, LNCS 2612, pp. 328-443, 2003. Springer-Verlagy Berlin Heidelberg 2003
 *
 *  Numbers reference steps of `Algorithm SPA-resistant Width-w NAF with Odd Scalar` on pp. 335
 */
static int secp256k1_ecdh_wnaf(int *wnaf, secp256k1_scalar_t s, int w) {
    int global_sign = 1;
    int skew = 0;
    int word = 0;
    /* 1 2 3 */
    int u_last;
    int u;

#ifdef USE_ENDOMORPHISM
    /* If we are using the endomorphism, we cannot handle even numbers by negating
     * them, since we are working with 128-bit numbers whose negations would be 256
     * bits, eliminating the performance advantage. Instead we use a technique from
     * Section 4.2 of the Okeya/Tagaki paper, which is to add either 1 (for even)
     * or 2 (for odd) to the number we are encoding, then compensating after the
     * multiplication. */
    /* Negative 128-bit numbers will be negated, since otherwise they are 256-bit */
    int flip = secp256k1_scalar_is_high(&s);
    /* We add 1 to even numbers, 2 to odd ones, noting that negation flips parity */
    int bit = flip ^ (s.d[0] & 1);
    /* We check for negative one, since adding 2 to it will cause an overflow */
    secp256k1_scalar_t neg_s;
    int not_neg_one;
    secp256k1_scalar_negate(&neg_s, &s);
    not_neg_one = !secp256k1_scalar_is_one(&neg_s);
    secp256k1_scalar_cadd_bit(&s, bit, not_neg_one);
    /* If we had negative one, flip == 1, s.d[0] == 0, bit == 1, so caller expects
     * that we added two to it and flipped it. In fact for -1 these operations are
     * identical. We only flipped, but since skewing is required (in the sense that
     * the skew must be 1 or 2, never zero) and flipping is not, we need to change
     * our flags to claim that we only skewed. */
    global_sign = secp256k1_scalar_cond_negate(&s, flip);
    global_sign *= not_neg_one * 2 - 1;
    skew = 1 << bit;
#else
    /* Otherwise, we just negate to force oddness */
    int is_even = secp256k1_scalar_is_even(&s);
    global_sign = secp256k1_scalar_cond_negate(&s, is_even);
#endif

    /* 4 */
    u_last = secp256k1_scalar_shr_int(&s, w);
    while (word * w < WNAF_BITS) {
        int sign;
        int even;

        /* 4.1 4.4 */
        u = secp256k1_scalar_shr_int(&s, w);
        /* 4.2 */
        even = ((u & 1) == 0);
        sign = 2 * (u_last > 0) - 1;
        u += sign * even;
        u_last -= sign * even * (1 << w);

        /* 4.3, adapted for global sign change */
        wnaf[word++] = u_last * global_sign;

        u_last = u;
    }
    wnaf[word] = u * global_sign;

    VERIFY_CHECK(secp256k1_scalar_is_zero(&s));
    VERIFY_CHECK(word == WNAF_SIZE(w));
    return skew;
}


static void secp256k1_point_multiply(secp256k1_gej_t *r, const secp256k1_ge_t *a, const secp256k1_scalar_t *scalar) {
    secp256k1_ge_t pre_a[ECMULT_TABLE_SIZE(WINDOW_A)];
    secp256k1_ge_t tmpa;
    secp256k1_fe_t Z;

#ifdef USE_ENDOMORPHISM
    secp256k1_ge_t pre_a_lam[ECMULT_TABLE_SIZE(WINDOW_A)];
    int wnaf_1[1 + WNAF_SIZE(WINDOW_A - 1)];
    int wnaf_lam[1 + WNAF_SIZE(WINDOW_A - 1)];
    int skew_1;
    int skew_lam;
    secp256k1_scalar_t q_1, q_lam;
#else
    int wnaf[1 + WNAF_SIZE(WINDOW_A - 1)];
#endif

    int i;
    secp256k1_scalar_t sc = *scalar;

    /* build wnaf representation for q. */
#ifdef USE_ENDOMORPHISM
    /* split q into q_1 and q_lam (where q = q_1 + q_lam*lambda, and q_1 and q_lam are ~128 bit) */
    secp256k1_scalar_split_lambda(&q_1, &q_lam, &sc);
    /* no need for zero correction when using endomorphism since even
     * numbers have one added to them anyway */
    skew_1   = secp256k1_ecdh_wnaf(wnaf_1,   q_1,   WINDOW_A - 1);
    skew_lam = secp256k1_ecdh_wnaf(wnaf_lam, q_lam, WINDOW_A - 1);
#else
    int is_zero = secp256k1_scalar_is_zero(scalar);
    /* the wNAF ladder cannot handle zero, so bump this to one .. we will
     * correct the result after the fact */
    sc.d[0] += is_zero;
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&sc));

    secp256k1_ecdh_wnaf(wnaf, sc, WINDOW_A - 1);
#endif

    /* Calculate odd multiples of a.
     * All multiples are brought to the same Z 'denominator', which is stored
     * in Z. Due to secp256k1' isomorphism we can do all operations pretending
     * that the Z coordinate was 1, use affine addition formulae, and correct
     * the Z coordinate of the result once at the end.
     */
    secp256k1_gej_set_ge(r, a);
    secp256k1_ecmult_odd_multiples_table_globalz_windowa(pre_a, &Z, r);
#ifdef USE_ENDOMORPHISM
    for (i = 0; i < ECMULT_TABLE_SIZE(WINDOW_A); i++) {
        secp256k1_ge_mul_lambda(&pre_a_lam[i], &pre_a[i]);
    }
#endif
    secp256k1_gej_set_infinity(r);

    for (i = WNAF_SIZE(WINDOW_A - 1); i >= 0; i--) {
        int n;
        int j;
        for (j = 0; j < WINDOW_A - 1; ++j) {
            /* This is a variable-time doubling, but it is actually constant-time for
             * nonzero points. We know on the first iteration that `r` will be zero
             * and know (by uniqueness of wNAF) that `r` will never be zero after
             * that iteration, so this does not result in a timing leak. */
            secp256k1_gej_double_var(r, r, NULL);
        }
#ifdef USE_ENDOMORPHISM
        n = wnaf_1[i];
        ECMULT_TABLE_GET_GE(&tmpa, pre_a, n, WINDOW_A);
        VERIFY_CHECK(n != 0);
        secp256k1_gej_add_ge(r, r, &tmpa);

        n = wnaf_lam[i];
        ECMULT_TABLE_GET_GE(&tmpa, pre_a_lam, n, WINDOW_A);
        VERIFY_CHECK(n != 0);
        secp256k1_gej_add_ge(r, r, &tmpa);
#else
        n = wnaf[i];
        VERIFY_CHECK(n != 0);
        ECMULT_TABLE_GET_GE(&tmpa, pre_a, n, WINDOW_A);
        secp256k1_gej_add_ge(r, r, &tmpa);
#endif
    }

    if (!r->infinity) {
        secp256k1_fe_mul(&r->z, &r->z, &Z);
    }

#ifdef USE_ENDOMORPHISM
    {
        /* Correct for wNAF skew */
        secp256k1_ge_t correction = *a;
        secp256k1_ge_storage_t correction_1_stor;
        secp256k1_ge_storage_t correction_lam_stor;
        secp256k1_ge_storage_t a2_stor;
        secp256k1_gej_t tmpj;
        secp256k1_gej_set_ge(&tmpj, &correction);
        secp256k1_gej_double_var(&tmpj, &tmpj, NULL);
        secp256k1_ge_set_gej(&correction, &tmpj);
        secp256k1_ge_to_storage(&correction_1_stor, a);
        secp256k1_ge_to_storage(&correction_lam_stor, a);
        secp256k1_ge_to_storage(&a2_stor, &correction);

        /* For odd numbers this is 2a (so replace it), for even ones a (so no-op) */
        secp256k1_ge_storage_cmov(&correction_1_stor, &a2_stor, skew_1 == 2);
        secp256k1_ge_storage_cmov(&correction_lam_stor, &a2_stor, skew_lam == 2);

        /* Apply the correction */
        secp256k1_ge_from_storage(&correction, &correction_1_stor);
        secp256k1_ge_neg(&correction, &correction);
        secp256k1_gej_add_ge(r, r, &correction);

        secp256k1_ge_from_storage(&correction, &correction_lam_stor);
        secp256k1_ge_neg(&correction, &correction);
        secp256k1_ge_mul_lambda(&correction, &correction);
        secp256k1_gej_add_ge(r, r, &correction);
    }
#else
    /* correct for zero */
    r->infinity |= is_zero;
#endif
}

#endif
