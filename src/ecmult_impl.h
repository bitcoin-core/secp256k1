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
#endif

#define WNAF_BITS 128
#define WNAF_SIZE_BITS(bits, w) CEIL_DIV(bits, w)
#define WNAF_SIZE(w) WNAF_SIZE_BITS(WNAF_BITS, w)

/* The number of objects allocated on the scratch space for ecmult_multi algorithms */
#define PIPPENGER_SCRATCH_OBJECTS 6
#define STRAUSS_SCRATCH_OBJECTS 5

#define PIPPENGER_MAX_BUCKET_WINDOW 12

/* Minimum number of points for which pippenger_wnaf is faster than strauss wnaf */
#define ECMULT_PIPPENGER_THRESHOLD 88

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

/** Number of points in a bundle. A bundle's first point is its anchor and the others are its
 *  followers. They are served together by one table: where the main loop of a multiplication would
 *  look up a multiple of each point and add it, it looks up one entry for the whole bundle and adds
 *  that. Larger bundles thus mean fewer additions there, at the cost of an exponentially larger
 *  table to build.
 *
 *  A bundle needs its anchor and at least one follower. It can have at most eight points, because
 *  each thing the main loop adds on its behalf is named in a byte with one bit per point: a
 *  follower's bit says whether it takes part, and the anchor, which always does, has the sign for
 *  its bit. */
#define ECMULT_BUNDLE_SIZE 6

#if !(2 <= ECMULT_BUNDLE_SIZE && ECMULT_BUNDLE_SIZE <= 8)
#  error "ECMULT_BUNDLE_SIZE must be in the range [2, 8]"
#endif

/** Number of entries in a bundle's table.
 *
 *  The scalars of a bundle are recoded so that the only combinations of its points the main loop
 *  ever asks for are those in which the anchor's coefficient is +1 or -1 and each follower's is
 *  either the same as the anchor's or zero: a sign times the sum of the anchor and some subset of
 *  the followers. There are 2^ECMULT_BUNDLE_SIZE of these, and the ones with a negative anchor are
 *  the negations of the ones with a positive anchor. So the table holds only the positive half,
 *  which is the subset sums that contain the anchor -- entry m is a[0] + sum(a[i+1] for the set
 *  bits i of m) -- and a negative anchor costs a negation at lookup. */
#define ECMULT_BUNDLE_TABLE_SIZE (((size_t)1) << (ECMULT_BUNDLE_SIZE - 1))

/** Build a bundle's table: the subset sums of its points that contain the anchor.
 *
 *  pre[m] receives a[0] + sum(a[i+1] for the set bits i of m), so it needs ECMULT_BUNDLE_TABLE_SIZE
 *  group elements. As in secp256k1_ecmult_odd_multiples_table these are Jacobian points with their z
 *  omitted, unusable until secp256k1_ecmult_bundle_table_set_globalz has run.
 *
 *  The entries are computed in Gray code order, in which consecutive ones differ by a single
 *  follower. Each entry is thus the one before it plus or minus an input point, and the table is a
 *  single chain of mixed additions with one live accumulator. A chain is also what lets z ratios
 *  bring every entry to a common z without an inversion. (Forming each subset sum from a smaller one
 *  takes one addition per entry as well, but those additions make a tree, whose inner entries have
 *  to be kept in Jacobian form and whose z values do not follow one from another.) The ratios go to
 *  zr, which needs ECMULT_BUNDLE_TABLE_SIZE field elements and is indexed by position in the chain,
 *  not by entry -- position k holds entry k ^ (k >> 1).
 *
 *  On entry *z is the z the chain has reached, 1 at its start; on return it is the z the chain has
 *  reached after this bundle. Bundles thus extend one chain instead of each having a denominator of
 *  its own, and one backward pass brings all of them to the last one's z.
 *
 *  Any input may be infinity, and an entry may be infinity even when no input is, a subset sum being
 *  able to vanish: a follower opposite to the anchor does it at once, and chosen inputs can do it
 *  deeper in. Such an entry is an ordinary infinite secp256k1_ge.
 */
static void secp256k1_ecmult_bundle_table(secp256k1_ge *pre, secp256k1_fe *zr, secp256k1_fe *z, const secp256k1_ge *a) {
    secp256k1_ge_z cur;
    size_t k;

    /* Entry 0 is the anchor by itself, brought onto the chain's curve by adding it to that curve's
     * infinity, which copes with an infinite anchor and leaves the ratio at 1: entry 0 sits at the
     * incoming z. (Like secp256k1_ge_table_set_globalz, secp256k1_ecmult_bundle_table_set_globalz
     * does not read zr[0].) */
    secp256k1_ge_z_set_infinity(&cur, z);
    secp256k1_ge_z_add_ge_var(&cur, &cur, &a[0], &zr[0]);
    pre[0] = cur.p;

    for (k = 1; k < ECMULT_BUNDLE_TABLE_SIZE; ++k) {
        /* The Gray code k ^ (k >> 1) differs from its predecessor in follower ctz(k) alone, which is
         * being added where that bit is now set and taken away where it is not. Taking away is just
         * adding the negation, so every step is one addition of an affine point. */
        size_t g = k ^ (k >> 1);
        int c = secp256k1_ctz32_var((uint32_t)k);
        secp256k1_ge t;

        if ((g >> c) & 1) {
            t = a[c + 1];
        } else {
            secp256k1_ge_neg(&t, &a[c + 1]);
        }
        secp256k1_ge_z_add_ge_var(&cur, &cur, &t, &zr[k]);
        pre[g] = cur.p;
    }

    *z = cur.z;
}

/** Bring one bundle's table onto the denominator the whole chain ends at.
 *
 *  As secp256k1_ge_table_set_globalz, but for a chain whose entries sit at their subset index rather
 *  than in chain order, and which may hold infinities, whose coordinates are left alone.
 *
 *  *zs is the ratio between the chain's final z and the z this bundle's last entry was left at, which
 *  is 1 for the bundle the chain ends with. On return it is that same ratio for the bundle before this
 *  one, so bundles are normalized from the last back to the first and every table ends up sharing the
 *  chain's final z.
 */
static void secp256k1_ecmult_bundle_table_set_globalz(secp256k1_ge *pre, const secp256k1_fe *zr, secp256k1_fe *zs) {
    size_t k = ECMULT_BUNDLE_TABLE_SIZE;

    while (k-- > 0) {
        size_t g = k ^ (k >> 1);

        if (!pre[g].infinity) {
            secp256k1_ge_set_ge_zinv(&pre[g], &pre[g], zs);
        }
        if (k > 0) {
            secp256k1_fe_mul(zs, zs, &zr[k]);
        }
    }
}

/** Fill x with the x coordinates of the lambda multiples of a bundle table's entries, so that one
 *  table serves both sides of the lambda split. Multiplying x by beta is all it takes. */
static void secp256k1_ecmult_bundle_table_lambda_x(secp256k1_fe *x, const secp256k1_ge *pre) {
    size_t i;

    for (i = 0; i < ECMULT_BUNDLE_TABLE_SIZE; ++i) {
        secp256k1_fe_mul(&x[i], &pre[i].x, &secp256k1_const_beta);
    }
}

/** Layout of a bundle index, the byte that names one thing for the main loop to add on a bundle's
 *  behalf: the number of a table entry, one bit per follower, and above it the anchor's sign, 1
 *  meaning positive and 0 that the entry is to be negated. */
#define ECMULT_BUNDLE_INDEX_SIGN (1U << (ECMULT_BUNDLE_SIZE - 1))
#define ECMULT_BUNDLE_INDEX_ENTRY (ECMULT_BUNDLE_INDEX_SIGN - 1U)

/** Put in r the point a bundle index selects: the table entry it names, negated when its sign bit
 *  is clear. Copying the whole element carries the infinity flag, which an entry can have. */
SECP256K1_INLINE static void secp256k1_ecmult_bundle_table_get_ge(secp256k1_ge *r, const secp256k1_ge *pre, unsigned int idx) {
    VERIFY_CHECK(idx < 2 * ECMULT_BUNDLE_INDEX_SIGN);

    *r = pre[idx & ECMULT_BUNDLE_INDEX_ENTRY];
    if (!(idx & ECMULT_BUNDLE_INDEX_SIGN)) {
        secp256k1_fe_negate(&r->y, &r->y, 1);
    }
}

/** As secp256k1_ecmult_bundle_table_get_ge, but for the lambda multiples of the table's points, whose
 *  x coordinates are the ones secp256k1_ecmult_bundle_table_lambda_x prepared. Only x differs, y and
 *  the omitted z being left alone by lambda, and negation works the same way on that side since lambda
 *  is a homomorphism.
 *
 *  This cannot be written in terms of secp256k1_ge_set_xy the way secp256k1_ecmult_table_get_ge_lambda
 *  is: that clears the infinity flag, which an entry here may need to keep. */
SECP256K1_INLINE static void secp256k1_ecmult_bundle_table_get_ge_lambda(secp256k1_ge *r, const secp256k1_ge *pre, const secp256k1_fe *x, unsigned int idx) {
    unsigned int m = idx & ECMULT_BUNDLE_INDEX_ENTRY;
    VERIFY_CHECK(idx < 2 * ECMULT_BUNDLE_INDEX_SIGN);

    r->infinity = pre[m].infinity;
    r->x = x[m];
    r->y = pre[m].y;
    if (!(idx & ECMULT_BUNDLE_INDEX_SIGN)) {
        secp256k1_fe_negate(&r->y, &r->y, 1);
    }
}

/** Number of 32-bit words in a secp256k1_hscalar: at least five, since a half of a lambda split
 *  takes up to 128 bits and a sign, and at most the eight of a scalar. */
#define ECMULT_HSCALAR_WORDS 5

#if !(5 <= ECMULT_HSCALAR_WORDS && ECMULT_HSCALAR_WORDS <= 8)
#  error "ECMULT_HSCALAR_WORDS must be in the range [5, 8]"
#endif

/** A half-scalar: a signed integer in two's complement, as little-endian 32-bit words.
 *
 *  The halves that secp256k1_scalar_split_lambda produces are small signed integers, but a
 *  secp256k1_scalar holds them as residues mod n, a negative one as n minus its magnitude. A recoding
 *  of such halves wants them as the integers they are, to add them, complement them and read off
 *  their bits, and this type is that: plain fixed-width arithmetic with the sign in the top bit. It
 *  is wider than any half, so that what a recoding computes from halves has bits to spare above it.
 *  Those are sign extension, and let a value outside its expected range be caught under VERIFY (see
 *  secp256k1_hscalar_verify_bits) instead of wrapping.
 */
typedef struct {
    uint32_t d[ECMULT_HSCALAR_WORDS];
} secp256k1_hscalar;

/** Set r to the signed integer a scalar stands for: the residue a itself when it is below 2^255, and
 *  a - n otherwise. Reading the sign off the top bit is right for every integer in [2^255 - n, 2^255),
 *  which takes in every absolute value up to 2^254, far beyond anything a lambda split produces. The
 *  value must then fit the type, that is lie in [-2^159, 2^159) at ECMULT_HSCALAR_WORDS = 5, which is
 *  checked under VERIFY.
 *
 *  Since a - n = a + (2^256 - n) mod 2^256, the conversion is a conditional addition of 2^256 - n to
 *  the low words of a, with the sign bit as the condition: no comparison and no negation.
 */
static void secp256k1_hscalar_set_scalar(secp256k1_hscalar *r, const secp256k1_scalar *a) {
    /* 2^256 - n, low word first. For an exhaustive test group every scalar is tiny, so the sign bit
     * is never set and the constant is never added; it only has to be well defined. */
#if defined(EXHAUSTIVE_TEST_ORDER)
    static const uint32_t n_c[8] = {
        (uint32_t)0 - (uint32_t)EXHAUSTIVE_TEST_ORDER, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul,
        0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul, 0xFFFFFFFFul
    };
#else
    static const uint32_t n_c[8] = {
        0x2FC9BEBFul, 0x402DA173ul, 0x50B75FC4ul, 0x45512319ul, 1, 0, 0, 0
    };
#endif
    uint32_t mask = 0 - secp256k1_scalar_get_bits_limb32(a, 255, 1);
    uint64_t c = 0;
    int k;

    for (k = 0; k < ECMULT_HSCALAR_WORDS; ++k) {
        c += (uint64_t)secp256k1_scalar_get_bits_limb32(a, 32 * (unsigned int)k, 32) + (n_c[k] & mask);
        r->d[k] = (uint32_t)c;
        c >>= 32;
    }
#ifdef VERIFY
    /* The words left off must be the sign extension of the ones kept. */
    {
        uint32_t sign = 0 - (r->d[ECMULT_HSCALAR_WORDS - 1] >> 31);

        for (k = ECMULT_HSCALAR_WORDS; k < 8; ++k) {
            c += (uint64_t)secp256k1_scalar_get_bits_limb32(a, 32 * (unsigned int)k, 32) + (n_c[k] & mask);
            VERIFY_CHECK((uint32_t)c == sign);
            c >>= 32;
        }
    }
#endif
}

/** Set r to a + b, modulo 2^(32*ECMULT_HSCALAR_WORDS); exact for the ranges the callers keep to. */
static void secp256k1_hscalar_add(secp256k1_hscalar *r, const secp256k1_hscalar *a, const secp256k1_hscalar *b) {
    uint64_t c = 0;
    int k;

    for (k = 0; k < ECMULT_HSCALAR_WORDS; ++k) {
        c += (uint64_t)a->d[k] + b->d[k];
        r->d[k] = (uint32_t)c;
        c >>= 32;
    }
}

/** Set r to the bitwise complement of a, which as an integer is -a - 1. */
static void secp256k1_hscalar_not(secp256k1_hscalar *r, const secp256k1_hscalar *a) {
    int k;

    for (k = 0; k < ECMULT_HSCALAR_WORDS; ++k) {
        r->d[k] = ~a->d[k];
    }
}

/** Set r to the bitwise XOR of a and b. */
static void secp256k1_hscalar_xor(secp256k1_hscalar *r, const secp256k1_hscalar *a, const secp256k1_hscalar *b) {
    int k;

    for (k = 0; k < ECMULT_HSCALAR_WORDS; ++k) {
        r->d[k] = a->d[k] ^ b->d[k];
    }
}

/** Bit j of a. */
SECP256K1_INLINE static unsigned int secp256k1_hscalar_bit(const secp256k1_hscalar *a, int j) {
    return (a->d[j >> 5] >> (j & 31)) & 1;
}

/** Check that a fits in bits-bit two's complement, that is, that every bit from bits-1 up is the
 *  sign (no-op unless VERIFY is enabled). */
SECP256K1_INLINE static void secp256k1_hscalar_verify_bits(const secp256k1_hscalar *a, int bits) {
#ifdef VERIFY
    unsigned int sign = secp256k1_hscalar_bit(a, 32 * ECMULT_HSCALAR_WORDS - 1);
    int j;

    for (j = bits - 1; j < 32 * ECMULT_HSCALAR_WORDS; ++j) {
        VERIFY_CHECK(secp256k1_hscalar_bit(a, j) == sign);
    }
#else
    (void)a;
    (void)bits;
#endif
}

/* How a bundle's scalars are recoded.
 *
 * Fix one side of the lambda split. Let u be the anchor's half there, written in L-bit two's
 * complement, where L is ECMULT_BUNDLE_BITS: bit j has weight 2^j, except the top bit, bit L-1,
 * whose weight is -2^(L-1). Changing bit j of ~u into bit j of u changes the value by
 *
 *     t_j = (2*u_j - 1) * weight_j,
 *
 * which is +2^j where u_j is set and -2^j where it is clear, the other way round at the top bit.
 *
 * The anchor is given the term t_j at every position. Changing every bit turns ~u into u, so its
 * terms sum to u - ~u = 2*u + 1, which is its coefficient on this side.
 *
 * A follower is given t_j at the positions where it is present and nothing at the others. Changing
 * the bits at those positions alone turns ~u into some e, so the follower's coefficient is e - ~u.
 * For that to be its own half f,
 *
 *     e = f + ~u,    present = ~(e ^ u),
 *
 * present being where e agrees with u. Every L-bit e comes from exactly one choice of positions, so
 * the recoding exists and is unique exactly when f + ~u fits in L bits. It is a closed form: one
 * addition and one XNOR per follower per side, with no pass over the positions.
 */

/** Number of positions a bundle's scalars are recoded into on each side of the lambda split, and so
 *  the number of doublings a main loop over them makes. This is L above.
 *
 *  It has to be large enough for u and for f + ~u to fit in L-bit two's complement, that is for
 *
 *      -2^(L-1) <= u < 2^(L-1)   and   -2^(L-1) <= f - u - 1 < 2^(L-1),
 *
 *  which |u| + |f| < 2^(L-1) ensures. Every half produced by secp256k1_scalar_split_lambda is below
 *  (a1 + a2 + 1)/2 = 0.6354*2^128 in absolute value (see the proof above
 *  secp256k1_scalar_split_lambda_verify), so |u| + |f| can reach 1.271*2^128. At L = 129 the room is
 *  2^128, short by a factor of 1.27; at L = 130 it is 2^129, a factor of 1.57 to spare. The anchor
 *  alone would fit in 129; it is a follower's f + ~u that needs the extra bit.
 *
 *  L also has to stay below the width of a half-scalar, which needs a bit above the L positions
 *  for a value that does not fit to show as such. */
#define ECMULT_BUNDLE_BITS 130

#if !(130 <= ECMULT_BUNDLE_BITS && ECMULT_BUNDLE_BITS < 32 * ECMULT_HSCALAR_WORDS)
#  error "ECMULT_BUNDLE_BITS must be in the range [130, 32*ECMULT_HSCALAR_WORDS - 1]"
#endif

/* The anchor's coefficient on each side is 2*u + 1 for its half u there (see above), so halves u
 * and u' give it (2*u + 1) + lambda*(2*u' + 1) = 2*(u + lambda*u') + (1 + lambda) in all. Splitting
 * t = (q + K)/2 for the anchor's scalar q therefore yields exactly q when K = -(1 + lambda).
 * Since lambda^2 + lambda + 1 = 0 mod n, that is the same as K = lambda^2, the other primitive
 * cube root of unity mod n and the inverse of lambda.
 *
 * This is the scalar offsetting of secp256k1_ecmult_const_gej; see the derivation in its comment.
 * The correction has to go into the scalar, before the split, because that is where there is
 * arithmetic mod n. The halves are plain integers: they cannot take a modular correction, and
 * the alternatives are ugly. */
#if defined(EXHAUSTIVE_TEST_ORDER)
static const secp256k1_scalar secp256k1_ecmult_bundle_K = ((EXHAUSTIVE_TEST_ORDER - 1U) * (1U + EXHAUSTIVE_TEST_LAMBDA)) % EXHAUSTIVE_TEST_ORDER;
#else
static const secp256k1_scalar secp256k1_ecmult_bundle_K = SECP256K1_SCALAR_CONST(
    0xac9c52b3ul, 0x3fa3cf1ful, 0x5ad9e3fdul, 0x77ed9ba4ul,
    0xa880b9fcul, 0x8ec739c2ul, 0xe0cfc810ul, 0xb51283ceul
);
#endif

/** Recode a bundle's scalars into one bundle index per position per side.
 *
 *  indices needs 2*ECMULT_BUNDLE_BITS bytes. indices[j] receives position j's index for the plain
 *  side and indices[ECMULT_BUNDLE_BITS + j] the one for the lambda side, in the layout
 *  ECMULT_BUNDLE_INDEX_SIGN and ECMULT_BUNDLE_INDEX_ENTRY describe.
 *
 *  na points to ECMULT_BUNDLE_SIZE scalars, na[0] being the anchor's. Any scalar is acceptable,
 *  including zero.
 *
 *  On each side, with u the anchor's half and f a follower's (see "How a bundle's scalars are
 *  recoded" above): the sign bit of the index at position j is bit j of u, inverted at the top
 *  position, and the follower's entry bit there is bit j of ~((f + ~u) ^ u).
 */
static void secp256k1_ecmult_bundle_recode(unsigned char *indices, const secp256k1_scalar *na) {
    secp256k1_hscalar u[2], signs[2];
    secp256k1_hscalar present[2][ECMULT_BUNDLE_SIZE - 1];
    secp256k1_scalar t, h[2];
    int j, side;
    size_t i;

    /* The anchor's halves, from (q + K)/2. */
    secp256k1_scalar_add(&t, &na[0], &secp256k1_ecmult_bundle_K);
    secp256k1_scalar_half(&t, &t);
    secp256k1_scalar_split_lambda(&h[0], &h[1], &t);

    for (side = 0; side < 2; ++side) {
        secp256k1_hscalar_set_scalar(&u[side], &h[side]);
        secp256k1_hscalar_verify_bits(&u[side], ECMULT_BUNDLE_BITS);
        /* The sign bits: u with bit L-1 flipped. Nothing reads them above that bit. */
        signs[side] = u[side];
        signs[side].d[(ECMULT_BUNDLE_BITS - 1) >> 5] ^= (uint32_t)1 << ((ECMULT_BUNDLE_BITS - 1) & 31);
    }

    for (i = 1; i < ECMULT_BUNDLE_SIZE; ++i) {
        secp256k1_scalar c[2];

        secp256k1_scalar_split_lambda(&c[0], &c[1], &na[i]);
        for (side = 0; side < 2; ++side) {
            secp256k1_hscalar *p = &present[side][i - 1];
            secp256k1_hscalar f, e;

            secp256k1_hscalar_set_scalar(&f, &c[side]);
            /* e = f + ~u, then present = ~(e ^ u). */
            secp256k1_hscalar_not(&e, &u[side]);
            secp256k1_hscalar_add(&e, &e, &f);
            secp256k1_hscalar_verify_bits(&e, ECMULT_BUNDLE_BITS);
            secp256k1_hscalar_xor(p, &e, &u[side]);
            secp256k1_hscalar_not(p, p);
        }
    }

    for (side = 0; side < 2; ++side) {
        for (j = 0; j < ECMULT_BUNDLE_BITS; ++j) {
            unsigned int idx = secp256k1_hscalar_bit(&signs[side], j) * ECMULT_BUNDLE_INDEX_SIGN;

            for (i = 1; i < ECMULT_BUNDLE_SIZE; ++i) {
                idx |= secp256k1_hscalar_bit(&present[side][i - 1], j) << (i - 1);
            }
            indices[side * ECMULT_BUNDLE_BITS + j] = (unsigned char)idx;
        }
    }
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

/** Number of points left over once as many full bundles as possible have been formed. They are
 *  handled as in Strauss' algorithm, in the same loop.
 *
 *  Bundles are never partly filled. A bundle costs the main loop 2*ECMULT_BUNDLE_BITS additions
 *  whether it is full or not, against roughly 2*129/(WINDOW_A+1) per point in Strauss' algorithm: a
 *  full bundle breaks even there (see secp256k1_ecmult_bundle_multi), and every point short of full
 *  puts it 43 additions behind, which its smaller table makes up for less and less. A bundle one
 *  point short might still come out ahead; it is not attempted here. Points left over cost no more
 *  than they would in Strauss' algorithm, so leaving them to it cannot lose. */
SECP256K1_INLINE static size_t secp256k1_ecmult_bundle_remainder(size_t num) {
    return num % ECMULT_BUNDLE_SIZE;
}

/** As secp256k1_ge_table_set_globalz, but threading the running ratio through *zs so that segments of
 *  one chain compose, and reading zr[0], which relates the segment's first entry to the z the chain
 *  arrived with. len must be at least 1. */
static void secp256k1_ecmult_bundle_chain_set_globalz(size_t len, secp256k1_ge *a, const secp256k1_fe *zr, secp256k1_fe *zs) {
    size_t i = len;

    VERIFY_CHECK(len >= 1);

    while (i-- > 0) {
        secp256k1_ge_set_ge_zinv(&a[i], &a[i], zs);
        secp256k1_fe_mul(zs, zs, &zr[i]);
    }
}

struct secp256k1_bundle_state {
    /* The tables of every bundle, concatenated. */
    secp256k1_ge *pre;
    /* The x coordinates of the lambda multiples of those tables. The same array first holds the
     * chain's z ratios, until the tables have been normalized and the ratios are spent. */
    secp256k1_fe *lamx;
    /* The bundle indices, 2*ECMULT_BUNDLE_BITS of them for each bundle in turn, as
     * secp256k1_ecmult_bundle_recode writes them. */
    unsigned char *indices;
    /* For the points left over: as in secp256k1_strauss_state, the odd multiples, then the x
     * coordinates of their lambda multiples, and the recoded scalars. */
    secp256k1_ge *pre_rem;
    secp256k1_fe *aux_rem;
    struct secp256k1_strauss_point_state *ps;
};

/** Set r to ng*G + sum(na[i] * a[i], i=0..num-1), taking the points in bundles. ng may be NULL.
 *
 *  The points are taken ECMULT_BUNDLE_SIZE at a time. In such a bundle the first point is the anchor
 *  and the others are its followers. Every scalar is split by lambda into two halves, and on each
 *  side of the split a bundle's halves are recoded together (secp256k1_ecmult_bundle_recode) so that
 *  at every position
 *
 *    - the anchor's digit is +1 or -1, never zero, and
 *    - each follower's digit is either zero or equal to the anchor's.
 *
 *  What a bundle contributes at one position on one side is then a sign times a sum of its points
 *  that always includes the anchor: an entry of the bundle's table of subset sums
 *  (secp256k1_ecmult_bundle_table) or its negation, named by one bundle index. That is one lookup
 *  and one addition per bundle, whatever the scalars are. The lambda side uses the same table with
 *  its x coordinates multiplied by beta.
 *
 *  Against Strauss' algorithm, which averages one addition per WINDOW_A + 1 positions for each half
 *  of each scalar, the main loop comes out even: at ECMULT_BUNDLE_SIZE = 6 a bundle spends
 *  2*ECMULT_BUNDLE_BITS = 260 additions where six points' wNAF digits spend about 12*129/6 = 258.
 *  The gain is in what goes before. A bundle's table takes 31 additions and 32 normalizations, where
 *  six tables of odd multiples take 42 additions, 6 doublings and 48 normalizations. The recoding of
 *  a scalar is a split and a few word operations, in place of a split and two wNAF recodings. And a
 *  bundle's table and indices occupy little more than half the space of what they replace.
 *
 *  Every bundle's table is a segment of one chain of additions, so a single backward pass brings
 *  them all to a common z, and the tables for G can then be used exactly as Strauss' algorithm uses
 *  them.
 *
 *  A zero scalar or an infinite point needs no special handling in a bundle: the recoding is valid
 *  for any scalar, and a table copes with infinite inputs and with subset sums that vanish.
 *
 *  The representation is the sign-aligned column form (GLV-SAC) of Faz-Hernandez, Longa and Sanchez,
 *  "Efficient and Secure Algorithms for GLV-Based Scalar Multiplication and their Implementation on
 *  GLV-GLS Curves" (https://eprint.iacr.org/2013/158), section 3, with the columns running across
 *  the points of a bundle rather than across the sub-scalars of a single multiplication.
 *
 *  Points that do not fill a bundle are handled as in Strauss' algorithm, in the same loop and with
 *  their tables on the same chain; see secp256k1_ecmult_bundle_remainder. As there, they are skipped
 *  when their scalar is zero or they are infinite. num must be at least ECMULT_BUNDLE_SIZE.
 */
static void secp256k1_ecmult_bundle_multi(const struct secp256k1_bundle_state *state, secp256k1_gej *r, size_t num, const secp256k1_ge *a, const secp256k1_scalar *na, const secp256k1_scalar *ng) {
    const size_t rem_table = ECMULT_TABLE_SIZE(WINDOW_A);
    secp256k1_fe globalz, zs;
    secp256k1_scalar ng_1, ng_128;
    int wnaf_ng_1[129];
    int wnaf_ng_128[129];
    int bits_ng_1 = 0;
    int bits_ng_128 = 0;
    size_t i, b, nbund, nbp, no;
    int pos;

    VERIFY_CHECK(num >= ECMULT_BUNDLE_SIZE);

    nbp = num - secp256k1_ecmult_bundle_remainder(num);
    nbund = nbp / ECMULT_BUNDLE_SIZE;

    /* Recode each bundle's scalars. */
    for (b = 0; b < nbund; ++b) {
        secp256k1_ecmult_bundle_recode(state->indices + b * 2 * ECMULT_BUNDLE_BITS, na + b * ECMULT_BUNDLE_SIZE);
    }

    /* One chain, over every bundle's table. */
    secp256k1_fe_set_int(&globalz, 1);
    for (b = 0; b < nbund; ++b) {
        secp256k1_ecmult_bundle_table(state->pre + b * ECMULT_BUNDLE_TABLE_SIZE,
                                      state->lamx + b * ECMULT_BUNDLE_TABLE_SIZE, &globalz,
                                      a + b * ECMULT_BUNDLE_SIZE);
    }
    /* It carries on through the odd multiples of each point left over. */
    no = 0;
    for (i = nbp; i < num; ++i) {
        secp256k1_gej tmp;
        secp256k1_scalar na_1, na_lam;

        if (secp256k1_scalar_is_zero(&na[i]) || secp256k1_ge_is_infinity(&a[i])) {
            continue;
        }
        secp256k1_scalar_split_lambda(&na_1, &na_lam, &na[i]);
        state->ps[no].bits_na_1   = secp256k1_ecmult_wnaf_small(state->ps[no].wnaf_na_1,   129, &na_1,   WINDOW_A);
        state->ps[no].bits_na_lam = secp256k1_ecmult_wnaf_small(state->ps[no].wnaf_na_lam, 129, &na_lam, WINDOW_A);
        VERIFY_CHECK(state->ps[no].bits_na_1 <= 129);
        VERIFY_CHECK(state->ps[no].bits_na_lam <= 129);

        /* The input is affine, so unlike in Strauss' algorithm the first ratio of this segment needs
         * no correcting: rescaling takes its z straight to the running one. */
        secp256k1_gej_set_ge(&tmp, &a[i]);
        secp256k1_gej_rescale(&tmp, &globalz);
        secp256k1_ecmult_odd_multiples_table(rem_table, state->pre_rem + no * rem_table,
                                             state->aux_rem + no * rem_table, &globalz, &tmp);
        ++no;
    }

    /* Bring every segment onto the z the chain ends at, walking it backwards from there. */
    secp256k1_fe_set_int(&zs, 1);
    for (i = no; i-- > 0;) {
        secp256k1_ecmult_bundle_chain_set_globalz(rem_table, state->pre_rem + i * rem_table,
                                                  state->aux_rem + i * rem_table, &zs);
    }
    for (b = nbund; b-- > 0;) {
        secp256k1_ecmult_bundle_table_set_globalz(state->pre + b * ECMULT_BUNDLE_TABLE_SIZE,
                                                  state->lamx + b * ECMULT_BUNDLE_TABLE_SIZE, &zs);
    }
    /* The lambda multiples can only be derived once the tables are there, and they overwrite the
     * ratios, which are spent. */
    for (b = 0; b < nbund; ++b) {
        secp256k1_ecmult_bundle_table_lambda_x(state->lamx + b * ECMULT_BUNDLE_TABLE_SIZE,
                                               state->pre + b * ECMULT_BUNDLE_TABLE_SIZE);
    }
    for (i = 0; i < no * rem_table; ++i) {
        secp256k1_fe_mul(&state->aux_rem[i], &state->pre_rem[i].x, &secp256k1_const_beta);
    }

    if (ng) {
        /* The G tables are unchanged from Strauss' algorithm, as is how they are used. */
        secp256k1_scalar_split_128(&ng_1, &ng_128, ng);
        bits_ng_1   = secp256k1_ecmult_wnaf(wnaf_ng_1,   129, &ng_1,   WINDOW_G);
        bits_ng_128 = secp256k1_ecmult_wnaf(wnaf_ng_128, 129, &ng_128, WINDOW_G);
        VERIFY_CHECK(bits_ng_1 <= 129);
        VERIFY_CHECK(bits_ng_128 <= 129);
    }

    secp256k1_gej_set_infinity(r);

    /* Nothing here runs for more positions than the bundles do: every wNAF stream is at most 129
     * digits and ECMULT_BUNDLE_BITS is 130, so the count is not a maximum over the streams as it is
     * in Strauss' algorithm. */
    for (pos = ECMULT_BUNDLE_BITS - 1; pos >= 0; --pos) {
        secp256k1_ge tmpa;
        int n;

        secp256k1_gej_double_var(r, r, NULL);
        for (b = 0; b < nbund; ++b) {
            const secp256k1_ge *pre = state->pre + b * ECMULT_BUNDLE_TABLE_SIZE;
            const unsigned char *indices = state->indices + b * 2 * ECMULT_BUNDLE_BITS;

            secp256k1_ecmult_bundle_table_get_ge(&tmpa, pre, indices[pos]);
            secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            secp256k1_ecmult_bundle_table_get_ge_lambda(&tmpa, pre, state->lamx + b * ECMULT_BUNDLE_TABLE_SIZE, indices[ECMULT_BUNDLE_BITS + pos]);
            secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
        }
        /* The points left over, exactly as Strauss' algorithm handles them. */
        for (i = 0; i < no; ++i) {
            if (pos < state->ps[i].bits_na_1 && (n = state->ps[i].wnaf_na_1[pos])) {
                secp256k1_ecmult_table_get_ge(&tmpa, state->pre_rem + i * rem_table, n, WINDOW_A);
                secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
            if (pos < state->ps[i].bits_na_lam && (n = state->ps[i].wnaf_na_lam[pos])) {
                secp256k1_ecmult_table_get_ge_lambda(&tmpa, state->pre_rem + i * rem_table, state->aux_rem + i * rem_table, n, WINDOW_A);
                secp256k1_gej_add_ge_var(r, r, &tmpa, NULL);
            }
        }
        if (pos < bits_ng_1 && (n = wnaf_ng_1[pos])) {
            secp256k1_ecmult_table_get_ge_storage(&tmpa, secp256k1_pre_g, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &globalz);
        }
        if (pos < bits_ng_128 && (n = wnaf_ng_128[pos])) {
            secp256k1_ecmult_table_get_ge_storage(&tmpa, secp256k1_pre_g_128, n, WINDOW_G);
            secp256k1_gej_add_zinv_var(r, r, &tmpa, &globalz);
        }
    }

    if (!secp256k1_gej_is_infinity(r)) {
        secp256k1_fe_mul(&r->z, &r->z, &globalz);
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

static size_t secp256k1_strauss_scratch_size(size_t n_points) {
    static const size_t point_size = (sizeof(secp256k1_ge) + sizeof(secp256k1_fe)) * ECMULT_TABLE_SIZE(WINDOW_A) + sizeof(struct secp256k1_strauss_point_state) + sizeof(secp256k1_gej) + sizeof(secp256k1_scalar);
    return n_points*point_size;
}

static int secp256k1_ecmult_strauss_batch(const secp256k1_callback* error_callback, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n_points, size_t cb_offset) {
    secp256k1_gej* points;
    secp256k1_scalar* scalars;
    struct secp256k1_strauss_state state;
    size_t i;
    const size_t scratch_checkpoint = secp256k1_scratch_checkpoint(error_callback, scratch);

    secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n_points == 0) {
        return 1;
    }

    /* We allocate STRAUSS_SCRATCH_OBJECTS objects on the scratch space. If these
     * allocations change, make sure to update the STRAUSS_SCRATCH_OBJECTS
     * constant and strauss_scratch_size accordingly. */
    points = (secp256k1_gej*)secp256k1_scratch_alloc(error_callback, scratch, n_points * sizeof(secp256k1_gej));
    scalars = (secp256k1_scalar*)secp256k1_scratch_alloc(error_callback, scratch, n_points * sizeof(secp256k1_scalar));
    state.aux = (secp256k1_fe*)secp256k1_scratch_alloc(error_callback, scratch, n_points * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_fe));
    state.pre_a = (secp256k1_ge*)secp256k1_scratch_alloc(error_callback, scratch, n_points * ECMULT_TABLE_SIZE(WINDOW_A) * sizeof(secp256k1_ge));
    state.ps = (struct secp256k1_strauss_point_state*)secp256k1_scratch_alloc(error_callback, scratch, n_points * sizeof(struct secp256k1_strauss_point_state));

    if (points == NULL || scalars == NULL || state.aux == NULL || state.pre_a == NULL || state.ps == NULL) {
        secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    for (i = 0; i < n_points; i++) {
        secp256k1_ge point;
        if (!cb(&scalars[i], &point, i+cb_offset, cbdata)) {
            secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
            return 0;
        }
        secp256k1_gej_set_ge(&points[i], &point);
    }
    secp256k1_ecmult_strauss_wnaf(&state, r, n_points, points, scalars, inp_g_sc);
    secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
    return 1;
}

/* Wrapper for secp256k1_ecmult_multi_func interface */
static int secp256k1_ecmult_strauss_batch_single(const secp256k1_callback* error_callback, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    return secp256k1_ecmult_strauss_batch(error_callback, scratch, r, inp_g_sc, cb, cbdata, n, 0);
}

static size_t secp256k1_strauss_max_points(const secp256k1_callback* error_callback, secp256k1_scratch *scratch) {
    return secp256k1_scratch_max_allocation(error_callback, scratch, STRAUSS_SCRATCH_OBJECTS) / secp256k1_strauss_scratch_size(1);
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

/**
 * Returns optimal bucket_window (number of bits of a scalar represented by a
 * set of buckets) for a given number of points.
 */
static int secp256k1_pippenger_bucket_window(size_t n) {
    if (n <= 1) {
        return 1;
    } else if (n <= 4) {
        return 2;
    } else if (n <= 20) {
        return 3;
    } else if (n <= 57) {
        return 4;
    } else if (n <= 136) {
        return 5;
    } else if (n <= 235) {
        return 6;
    } else if (n <= 1260) {
        return 7;
    } else if (n <= 4420) {
        return 9;
    } else if (n <= 7880) {
        return 10;
    } else if (n <= 16050) {
        return 11;
    } else {
        return PIPPENGER_MAX_BUCKET_WINDOW;
    }
}

/**
 * Returns the maximum optimal number of points for a bucket_window.
 */
static size_t secp256k1_pippenger_bucket_window_inv(int bucket_window) {
    switch(bucket_window) {
        case 1: return 1;
        case 2: return 4;
        case 3: return 20;
        case 4: return 57;
        case 5: return 136;
        case 6: return 235;
        case 7: return 1260;
        case 8: return 1260;
        case 9: return 4420;
        case 10: return 7880;
        case 11: return 16050;
        case PIPPENGER_MAX_BUCKET_WINDOW: return SIZE_MAX;
    }
    return 0;
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
 * Returns the scratch size required for a given number of points (excluding
 * base point G) without considering alignment.
 */
static size_t secp256k1_pippenger_scratch_size(size_t n_points, int bucket_window) {
    size_t entries = 2*n_points + 2;
    size_t entry_size = sizeof(secp256k1_ge) + sizeof(secp256k1_scalar) + sizeof(struct secp256k1_pippenger_point_state) + (WNAF_SIZE(bucket_window+1)+1)*sizeof(int);
    return (sizeof(secp256k1_gej) << bucket_window) + sizeof(struct secp256k1_pippenger_state) + entries * entry_size;
}

static int secp256k1_ecmult_pippenger_batch(const secp256k1_callback* error_callback, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n_points, size_t cb_offset) {
    const size_t scratch_checkpoint = secp256k1_scratch_checkpoint(error_callback, scratch);
    /* Use 2(n+1) with the endomorphism, when calculating batch
     * sizes. The reason for +1 is that we add the G scalar to the list of
     * other scalars. */
    size_t entries = 2*n_points + 2;
    secp256k1_ge *points;
    secp256k1_scalar *scalars;
    secp256k1_gej *buckets;
    struct secp256k1_pippenger_state *state_space;
    size_t idx = 0;
    size_t point_idx = 0;
    int bucket_window;

    secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n_points == 0) {
        return 1;
    }
    bucket_window = secp256k1_pippenger_bucket_window(n_points);

    /* We allocate PIPPENGER_SCRATCH_OBJECTS objects on the scratch space. If
     * these allocations change, make sure to update the
     * PIPPENGER_SCRATCH_OBJECTS constant and pippenger_scratch_size
     * accordingly. */
    points = (secp256k1_ge *) secp256k1_scratch_alloc(error_callback, scratch, entries * sizeof(*points));
    scalars = (secp256k1_scalar *) secp256k1_scratch_alloc(error_callback, scratch, entries * sizeof(*scalars));
    state_space = (struct secp256k1_pippenger_state *) secp256k1_scratch_alloc(error_callback, scratch, sizeof(*state_space));
    if (points == NULL || scalars == NULL || state_space == NULL) {
        secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
        return 0;
    }
    state_space->ps = (struct secp256k1_pippenger_point_state *) secp256k1_scratch_alloc(error_callback, scratch, entries * sizeof(*state_space->ps));
    state_space->wnaf_na = (int *) secp256k1_scratch_alloc(error_callback, scratch, entries*(WNAF_SIZE(bucket_window+1)) * sizeof(int));
    buckets = (secp256k1_gej *) secp256k1_scratch_alloc(error_callback, scratch, ((size_t)1 << bucket_window) * sizeof(*buckets));
    if (state_space->ps == NULL || state_space->wnaf_na == NULL || buckets == NULL) {
        secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
        return 0;
    }

    if (inp_g_sc != NULL) {
        scalars[0] = *inp_g_sc;
        points[0] = secp256k1_ge_const_g;
        idx++;
        secp256k1_ecmult_endo_split(&scalars[0], &scalars[1], &points[0], &points[1]);
        idx++;
    }

    while (point_idx < n_points) {
        if (!cb(&scalars[idx], &points[idx], point_idx + cb_offset, cbdata)) {
            secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
            return 0;
        }
        idx++;
        secp256k1_ecmult_endo_split(&scalars[idx - 1], &scalars[idx], &points[idx - 1], &points[idx]);
        idx++;
        point_idx++;
    }

    secp256k1_ecmult_pippenger_wnaf(buckets, bucket_window, state_space, r, scalars, points, idx);
    secp256k1_scratch_apply_checkpoint(error_callback, scratch, scratch_checkpoint);
    return 1;
}

/* Wrapper for secp256k1_ecmult_multi_func interface */
static int secp256k1_ecmult_pippenger_batch_single(const secp256k1_callback* error_callback, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    return secp256k1_ecmult_pippenger_batch(error_callback, scratch, r, inp_g_sc, cb, cbdata, n, 0);
}

/**
 * Returns the maximum number of points in addition to G that can be used with
 * a given scratch space. The function ensures that fewer points may also be
 * used.
 */
static size_t secp256k1_pippenger_max_points(const secp256k1_callback* error_callback, secp256k1_scratch *scratch) {
    size_t max_alloc = secp256k1_scratch_max_allocation(error_callback, scratch, PIPPENGER_SCRATCH_OBJECTS);
    int bucket_window;
    size_t res = 0;

    for (bucket_window = 1; bucket_window <= PIPPENGER_MAX_BUCKET_WINDOW; bucket_window++) {
        size_t n_points;
        size_t max_points = secp256k1_pippenger_bucket_window_inv(bucket_window);
        size_t space_for_points;
        size_t space_overhead;
        size_t entry_size = sizeof(secp256k1_ge) + sizeof(secp256k1_scalar) + sizeof(struct secp256k1_pippenger_point_state) + (WNAF_SIZE(bucket_window+1)+1)*sizeof(int);

        entry_size = 2*entry_size;
        space_overhead = (sizeof(secp256k1_gej) << bucket_window) + entry_size + sizeof(struct secp256k1_pippenger_state);
        if (space_overhead > max_alloc) {
            break;
        }
        space_for_points = max_alloc - space_overhead;

        n_points = space_for_points/entry_size;
        n_points = n_points > max_points ? max_points : n_points;
        if (n_points > res) {
            res = n_points;
        }
        if (n_points < max_points) {
            /* A larger bucket_window may support even more points. But if we
             * would choose that then the caller couldn't safely use any number
             * smaller than what this function returns */
            break;
        }
    }
    return res;
}

/* Computes ecmult_multi by simply multiplying and adding each point. Does not
 * require a scratch space */
static int secp256k1_ecmult_multi_simple_var(secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n_points) {
    size_t point_idx;
    secp256k1_gej tmpj;

    secp256k1_gej_set_infinity(r);
    secp256k1_gej_set_infinity(&tmpj);
    /* r = inp_g_sc*G */
    secp256k1_ecmult(r, &tmpj, &secp256k1_scalar_zero, inp_g_sc);
    for (point_idx = 0; point_idx < n_points; point_idx++) {
        secp256k1_ge point;
        secp256k1_gej pointj;
        secp256k1_scalar scalar;
        if (!cb(&scalar, &point, point_idx, cbdata)) {
            return 0;
        }
        /* r += scalar*point */
        secp256k1_gej_set_ge(&pointj, &point);
        secp256k1_ecmult(&tmpj, &pointj, &scalar, NULL);
        secp256k1_gej_add_var(r, r, &tmpj, NULL);
    }
    return 1;
}

/* Compute the number of batches and the batch size given the maximum batch size and the
 * total number of points */
static int secp256k1_ecmult_multi_batch_size_helper(size_t *n_batches, size_t *n_batch_points, size_t max_n_batch_points, size_t n) {
    if (max_n_batch_points == 0) {
        return 0;
    }
    if (max_n_batch_points > ECMULT_MAX_POINTS_PER_BATCH) {
        max_n_batch_points = ECMULT_MAX_POINTS_PER_BATCH;
    }
    if (n == 0) {
        *n_batches = 0;
        *n_batch_points = 0;
        return 1;
    }
    /* Compute ceil(n/max_n_batch_points) and ceil(n/n_batches) */
    *n_batches = CEIL_DIV(n, max_n_batch_points);
    *n_batch_points = CEIL_DIV(n, *n_batches);
    return 1;
}

typedef int (*secp256k1_ecmult_multi_func)(const secp256k1_callback* error_callback, secp256k1_scratch*, secp256k1_gej*, const secp256k1_scalar*, secp256k1_ecmult_multi_callback cb, void*, size_t);
static int secp256k1_ecmult_multi_var(const secp256k1_callback* error_callback, secp256k1_scratch *scratch, secp256k1_gej *r, const secp256k1_scalar *inp_g_sc, secp256k1_ecmult_multi_callback cb, void *cbdata, size_t n) {
    size_t i;

    int (*f)(const secp256k1_callback* error_callback, secp256k1_scratch*, secp256k1_gej*, const secp256k1_scalar*, secp256k1_ecmult_multi_callback cb, void*, size_t, size_t);
    size_t n_batches;
    size_t n_batch_points;

    secp256k1_gej_set_infinity(r);
    if (inp_g_sc == NULL && n == 0) {
        return 1;
    } else if (n == 0) {
        secp256k1_ecmult(r, r, &secp256k1_scalar_zero, inp_g_sc);
        return 1;
    }
    if (scratch == NULL) {
        return secp256k1_ecmult_multi_simple_var(r, inp_g_sc, cb, cbdata, n);
    }

    /* Compute the batch sizes for Pippenger's algorithm given a scratch space. If it's greater than
     * a threshold use Pippenger's algorithm. Otherwise use Strauss' algorithm.
     * As a first step check if there's enough space for Pippenger's algo (which requires less space
     * than Strauss' algo) and if not, use the simple algorithm. */
    if (!secp256k1_ecmult_multi_batch_size_helper(&n_batches, &n_batch_points, secp256k1_pippenger_max_points(error_callback, scratch), n)) {
        return secp256k1_ecmult_multi_simple_var(r, inp_g_sc, cb, cbdata, n);
    }
    if (n_batch_points >= ECMULT_PIPPENGER_THRESHOLD) {
        f = secp256k1_ecmult_pippenger_batch;
    } else {
        if (!secp256k1_ecmult_multi_batch_size_helper(&n_batches, &n_batch_points, secp256k1_strauss_max_points(error_callback, scratch), n)) {
            return secp256k1_ecmult_multi_simple_var(r, inp_g_sc, cb, cbdata, n);
        }
        f = secp256k1_ecmult_strauss_batch;
    }
    for(i = 0; i < n_batches; i++) {
        size_t nbp = n < n_batch_points ? n : n_batch_points;
        size_t offset = n_batch_points*i;
        secp256k1_gej tmp;
        if (!f(error_callback, scratch, &tmp, i == 0 ? inp_g_sc : NULL, cb, cbdata, nbp, offset)) {
            return 0;
        }
        secp256k1_gej_add_var(r, r, &tmp, NULL);
        n -= nbp;
    }
    return 1;
}

#endif /* SECP256K1_ECMULT_IMPL_H */
