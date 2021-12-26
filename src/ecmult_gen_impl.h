/*******************************************************************************
 * Copyright (c) 2013-2015, 2021 Pieter Wuille, Gregory Maxwell, Peter Dettman *
 * Distributed under the MIT software license, see the accompanying            *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.        *
 *******************************************************************************/

#ifndef SECP256K1_ECMULT_GEN_IMPL_H
#define SECP256K1_ECMULT_GEN_IMPL_H

#include "util.h"
#include "scalar.h"
#include "group.h"
#include "ecmult_gen.h"
#include "hash_impl.h"
#include "precomputed_ecmult_gen.h"

static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context *ctx) {
    secp256k1_ecmult_gen_blind(ctx, NULL);
    ctx->built = 1;
}

static int secp256k1_ecmult_gen_context_is_built(const secp256k1_ecmult_gen_context* ctx) {
    return ctx->built;
}

static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context *ctx) {
    ctx->built = 0;
    secp256k1_scalar_clear(&ctx->scalar_offset);
    secp256k1_ge_clear(&ctx->final_point_add);
}

static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    uint32_t comb_off;
    secp256k1_ge add;
    secp256k1_fe neg;
    secp256k1_ge_storage adds;
    secp256k1_scalar recoded;

    memset(&adds, 0, sizeof(adds));
    secp256k1_gej_set_infinity(r);

    /* We want to compute R = gn*G.
     *
     * To blind the scalar used in the computation, we rewrite this to be R = (gn-b)*G + b*G.
     *
     * Next, we write (gn-b)*G as a sum of values (2*bit_i-1) * 2^i * G, for i=0..COMB_BITS-1.
     * The values bit_i can be found as the binary representation of recoded =
     * (gn + 2^COMB_BITS - 1 - b)/2 (mod order).
     *
     * The value (2^COMB_BITS - 1 - b) is precomputed as ctx->scalar_offset, and bG is
     * precomputed as ctx->final_point_add. Thus recoded can be written as
     * recoded = (gn + scalar_offset)/2, and R becomes the sum of (2*bit_i-1)*2^i*G
     * values plus final_point_add. */

    /* Compute the recoded value as a scalar. */
    secp256k1_scalar_add(&recoded, gn, &ctx->scalar_offset);
    secp256k1_scalar_half(&recoded, &recoded);

    /* In secp256k1_ecmult_gen_prec_table we have precomputed sums of the
     * (2*bit_i-1) * 2^i * G points, for various combinations of i positions.
     * We will rewrite our equation in terms of these table entries, as explained
     * in Section 3.3 of "Fast and compact elliptic-curve cryptography" by
     * Mike Hamburg (see https://eprint.iacr.org/2012/309).
     *
     * Let mask(b) = sum(2^(b*COMB_TEETH + t)*COMB_SPACING for t=0..COMB_TEETH-1),
     * with b ranging from 0 to COMB_BLOCKS-1. So for example with COMB_BLOCKS=11,
     * COMB_TEETH=6, COMB_SPACING=4, we would have:
     *   mask(0)  = 2^0   + 2^4   + 2^8   + 2^12  + 2^16  + 2^20,
     *   mask(1)  = 2^24  + 2^28  + 2^32  + 2^36  + 2^40  + 2^44,
     *   mask(2)  = 2^48  + 2^52  + 2^56  + 2^60  + 2^64  + 2^68,
     *   ...
     *   mask(10) = 2^240 + 2^244 + 2^248 + 2^252 + 2^256 + 2^260
     *
     * Imagine we have a table(b,m) function which can look up, given b and
     * m=(recoded & mask(b)), the sum of (2*bit_i-1)*2^i*G for all bit positions
     * i set in mask(b). In our example, table(1, 2^28 + 2^44) would be equal to
     * (-2^24 + 2^28 + -2^32 + -2^36 + -2^40 + 2^244)*G.
     *
     * With that, we can rewrite R as:
     *   1*(table(0, recoded & mask(0)) + table(1, recoded & mask(1)) + ...)
     * + 2*(table(0, (recoded/2) & mask(0)) + table(1, (recoded/2) & mask(1)) + ...)
     * + 4*(table(0, (recoded/4) & mask(0)) + table(1, (recoded/4) & mask(1)) + ...)
     * + ...
     * + 2^(COMB_SPACING-1)*(table(0, (recoded/2^(COMB_SPACING-1)) & mask(0)) + ...)
     * + ctx->final_point_add.
     *
     * This is implemented using an outer loop that runs in reverse order over the lines
     * of this equation, which in each iteration runs an inner loop that adds the terms
     * of that line and the doubles the result before proceeding to the next line.
     * In pseudocode:
     *   R = infinity
     *   for comb_off in range(COMB_SPACING - 1, -1, -1):
     *     for block in range(COMB_BLOCKS):
     *       R += table(block, (recoded >> comb_off) & mask(block))
     *     if comb_off > 0:
     *       R = 2*R
     *   R += final_point_add
     *   return R
     *
     * The last question is how to implement the table(b,m) function. For any value of
     * b, m=(recoded & mask(b)) can only take on at most 2^COMB_TEETH possible values
     * (the last one may have fewer as there mask(b) may the curve order). So we could
     * create COMB_BLOCK tables which contain a value for each such m value.
     *
     * Due to the fact that every table entry is a sum of positive and negative powers
     * of two multiplied by G, every table will contains pairs of negated points:
     * if all the masked bits in m flip, the table value is negated. We can exploit this
     * to only store the first half of every table. If an entry from the second half is
     * needed, we look up its bit-flipped version instead, and conditionally negate it.
     *
     * secp256k1_ecmult_gen_prec_table[b][index] stores the table(b,m) entries. Index
     * is simply the relevant bits of m packed together without gaps. */

    /* Outer loop: iterate over comb_off from COMB_SPACING - 1 down to 0. */
    comb_off = COMB_SPACING - 1;
    while (1) {
        uint32_t block;
        uint32_t bit_pos = comb_off;
        /* Inner loop: for each block, add table entries to the result. */
        for (block = 0; block < COMB_BLOCKS; ++block) {
            /* Gather the mask(block)-selected bits of recoded into bits. They're packed
             * together: bit (tooth) of bits = bit
             * ((block*COMB_TEETH + tooth)*COMB_SPACING + comb_off) of recoded. */
            uint32_t bits = 0, sign, abs, index, tooth;
            for (tooth = 0; tooth < COMB_TEETH && bit_pos < 256; ++tooth) {
                uint32_t bit = secp256k1_scalar_get_bits(&recoded, bit_pos, 1);
                bits |= bit << tooth;
                bit_pos += COMB_SPACING;
            }

            /* If the top bit of bits is 1, conditionally flip them all (corresponding
             * to looking up the negated table value), and remember to negate the
             * result in sign. */
            sign = (bits >> (COMB_TEETH - 1)) & 1;
            abs = (bits ^ -sign) & (COMB_POINTS - 1);
            VERIFY_CHECK(sign == 0 || sign == 1);
            VERIFY_CHECK(abs < COMB_POINTS);

            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (https://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            for (index = 0; index < COMB_POINTS; ++index) {
                secp256k1_ge_storage_cmov(&adds, &secp256k1_ecmult_gen_prec_table[block][index], index == abs);
            }

            /* Set add=adds or add=-adds, in constant time, based on sign. */
            secp256k1_ge_from_storage(&add, &adds);
            secp256k1_fe_negate(&neg, &add.y, 1);
            secp256k1_fe_cmov(&add.y, &neg, sign);

            /* Add the looked up and conditionally negated value to r. */
            secp256k1_gej_add_ge(r, r, &add);
        }

        /* Double the result, except in the last iteration. */
        if (comb_off-- == 0) break;
        secp256k1_gej_double(r, r);
    }

    /* Correct for the scalar_offset added at the start (final_point_add = b*G, while b was
     * subtracted from the input scalar gn). */
    secp256k1_gej_add_ge(r, r, &ctx->final_point_add);

    /* Cleanup. */
    secp256k1_fe_clear(&neg);
    secp256k1_ge_clear(&add);
    memset(&adds, 0, sizeof(adds));
    secp256k1_scalar_clear(&recoded);
}

/* Setup blinding values for secp256k1_ecmult_gen. */
static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    secp256k1_scalar b;
    secp256k1_scalar base_offset, negone;
    unsigned i;
    secp256k1_gej gb;
    unsigned char nonce32[32];
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char keydata[64] = {0};

    /* Compute base_offset = 2^COMB_BITS - 1. This could be precomputed. */
    base_offset = secp256k1_scalar_one;
    secp256k1_scalar_negate(&negone, &base_offset);
    for (i = 0; i < COMB_BITS; ++i) {
        secp256k1_scalar_add(&base_offset, &base_offset, &base_offset);
    }
    secp256k1_scalar_add(&base_offset, &base_offset, &negone);

    if (seed32 == NULL) {
        /* When seed is NULL, reset the final point and blinding value. */
        secp256k1_ge_neg(&ctx->final_point_add, &secp256k1_ge_const_g);
        ctx->scalar_offset = secp256k1_scalar_one;
        secp256k1_scalar_add(&ctx->scalar_offset, &ctx->scalar_offset, &base_offset);
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    secp256k1_scalar_get_b32(nonce32, &ctx->scalar_offset);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    memcpy(keydata, nonce32, 32);
    if (seed32 != NULL) {
        memcpy(keydata + 32, seed32, 32);
    }
    secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, seed32 ? 64 : 32);
    memset(keydata, 0, sizeof(keydata));

    /* TODO: reintroduce projective blinding. */

    /* For a random blinding value b, set scalar_offset=base_offset-n, final_point_add=bG */
    secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    secp256k1_scalar_set_b32(&b, nonce32, NULL);
    /* The blinding value cannot be zero, as that would mean final_point_add = infinity,
     * which secp256k1_gej_add_ge cannot handle. */
    secp256k1_scalar_cmov(&b, &secp256k1_scalar_one, secp256k1_scalar_is_zero(&b));
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    secp256k1_ecmult_gen(ctx, &gb, &b);
    secp256k1_scalar_negate(&b, &b);
    secp256k1_scalar_add(&ctx->scalar_offset, &b, &base_offset);
    secp256k1_ge_set_gej(&ctx->final_point_add, &gb);

    /* Clean up. */
    secp256k1_scalar_clear(&b);
    secp256k1_gej_clear(&gb);
}

#endif /* SECP256K1_ECMULT_GEN_IMPL_H */
