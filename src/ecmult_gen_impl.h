/**********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell      *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_IMPL_H
#define SECP256K1_ECMULT_GEN_IMPL_H

#include "scalar.h"
#include "group.h"
#include "ecmult_gen.h"
#include "hash_impl.h"
#ifdef USE_ECMULT_STATIC_PRECOMPUTATION
#include "ecmult_static_context.h"
#endif
static void secp256k1_ecmult_gen_context_init(secp256k1_ecmult_gen_context *ctx) {
    ctx->prec = NULL;
}

static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context *ctx, const secp256k1_callback* cb) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
#if USE_COMB
    secp256k1_ge prec[COMB_POINTS_TOTAL + COMB_OFFSET];
    secp256k1_gej u, sum;
    int block, index, spacing, stride, tooth;
#else
    secp256k1_ge prec[1024];
    secp256k1_gej gj;
    secp256k1_gej nums_gej;
    int i, j;
#endif
#endif

    if (ctx->prec != NULL) {
        return;
    }
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
#if USE_COMB
    ctx->prec = (secp256k1_ge_storage (*)[COMB_BLOCKS][COMB_POINTS])checked_malloc(cb, sizeof(*ctx->prec));

    /* get the generator */
    secp256k1_gej_set_ge(&u, &secp256k1_ge_const_g);

    /* compute prec. */
    {
        secp256k1_gej ds[COMB_TEETH];
        secp256k1_gej vs[COMB_POINTS_TOTAL + COMB_OFFSET];
        int vs_pos = 0;

        for (block = 0; block < COMB_BLOCKS; ++block) {
            secp256k1_gej_set_infinity(&sum);
            for (tooth = 0; tooth < COMB_TEETH; ++tooth) {
                secp256k1_gej_add_var(&sum, &sum, &u, NULL);
                secp256k1_gej_double(&u, &u);
                ds[tooth] = u;
                if (block + tooth != COMB_BLOCKS + COMB_TEETH - 2) {
                    for (spacing = 1; spacing < COMB_SPACING; ++spacing) {
                        secp256k1_gej_double(&u, &u);
                    }
                }
            }
            secp256k1_gej_neg(&vs[vs_pos++], &sum);
            for (tooth = 0; tooth < (COMB_TEETH - 1); ++tooth) {
                stride = 1 << tooth;
                for (index = 0; index < stride; ++index, ++vs_pos) {
                    secp256k1_gej_add_var(&vs[vs_pos], &vs[vs_pos - stride], &ds[tooth], NULL);
                }
            }
        }
        VERIFY_CHECK(vs_pos == COMB_POINTS_TOTAL);
#if COMB_OFFSET
        vs[COMB_POINTS_TOTAL] = ds[COMB_TEETH - 1];
#endif
        secp256k1_ge_set_all_gej_var(prec, vs, COMB_POINTS_TOTAL + COMB_OFFSET, cb);
    }

    for (block = 0; block < COMB_BLOCKS; ++block) {
        for (index = 0; index < COMB_POINTS; ++index) {
            secp256k1_ge_to_storage(&(*ctx->prec)[block][index], &prec[block * COMB_POINTS + index]);
        }
    }

#if COMB_OFFSET
    ctx->offset = prec[COMB_POINTS_TOTAL];
#endif

#else
    ctx->prec = (secp256k1_ge_storage (*)[64][16])checked_malloc(cb, sizeof(*ctx->prec));

    /* get the generator */
    secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);

    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    {
        static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
        secp256k1_fe nums_x;
        secp256k1_ge nums_ge;
        int r;
        r = secp256k1_fe_set_b32(&nums_x, nums_b32);
        (void)r;
        VERIFY_CHECK(r);
        r = secp256k1_ge_set_xo_var(&nums_ge, &nums_x, 0);
        (void)r;
        VERIFY_CHECK(r);
        secp256k1_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        secp256k1_gej_add_ge_var(&nums_gej, &nums_gej, &secp256k1_ge_const_g, NULL);
    }

    /* compute prec. */
    {
        secp256k1_gej precj[1024]; /* Jacobian versions of prec. */
        secp256k1_gej gbase;
        secp256k1_gej numsbase;
        gbase = gj; /* 16^j * G */
        numsbase = nums_gej; /* 2^j * nums. */
        for (j = 0; j < 64; j++) {
            /* Set precj[j*16 .. j*16+15] to (numsbase, numsbase + gbase, ..., numsbase + 15*gbase). */
            precj[j*16] = numsbase;
            for (i = 1; i < 16; i++) {
                secp256k1_gej_add_var(&precj[j*16 + i], &precj[j*16 + i - 1], &gbase, NULL);
            }
            /* Multiply gbase by 16. */
            for (i = 0; i < 4; i++) {
                secp256k1_gej_double_var(&gbase, &gbase, NULL);
            }
            /* Multiply numbase by 2. */
            secp256k1_gej_double_var(&numsbase, &numsbase, NULL);
            if (j == 62) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                secp256k1_gej_neg(&numsbase, &numsbase);
                secp256k1_gej_add_var(&numsbase, &numsbase, &nums_gej, NULL);
            }
        }
        secp256k1_ge_set_all_gej_var(prec, precj, 1024, cb);
    }
    for (j = 0; j < 64; j++) {
        for (i = 0; i < 16; i++) {
            secp256k1_ge_to_storage(&(*ctx->prec)[j][i], &prec[j*16 + i]);
        }
    }
#endif
#else
    (void)cb;
#if USE_COMB
    ctx->prec = (secp256k1_ge_storage (*)[COMB_BLOCKS][COMB_POINTS])secp256k1_ecmult_gen_ctx_prec;
#if COMB_OFFSET
    secp256k1_ge_from_storage(&ctx->offset, &secp256k1_ecmult_gen_ctx_offset);
#endif
#else
    ctx->prec = (secp256k1_ge_storage (*)[64][16])secp256k1_ecmult_gen_ctx_prec;
#endif
#endif
    secp256k1_ecmult_gen_blind(ctx, NULL);
}

static int secp256k1_ecmult_gen_context_is_built(const secp256k1_ecmult_gen_context* ctx) {
    return ctx->prec != NULL;
}

static void secp256k1_ecmult_gen_context_clone(secp256k1_ecmult_gen_context *dst,
                                               const secp256k1_ecmult_gen_context *src, const secp256k1_callback* cb) {
    if (src->prec == NULL) {
        dst->prec = NULL;
    } else {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
#if USE_COMB
        dst->prec = (secp256k1_ge_storage (*)[COMB_BLOCKS][COMB_POINTS])checked_malloc(cb, sizeof(*dst->prec));
#else
        dst->prec = (secp256k1_ge_storage (*)[64][16])checked_malloc(cb, sizeof(*dst->prec));
#endif
        memcpy(dst->prec, src->prec, sizeof(*dst->prec));
#else
        (void)cb;
        dst->prec = src->prec;
#endif

#if USE_COMB
#if COMB_OFFSET
        dst->offset = src->offset;
#endif
#endif
        dst->initial = src->initial;
        dst->blind = src->blind;
    }
}

static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context *ctx) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    free(ctx->prec);
#endif
#if USE_COMB
#if COMB_OFFSET
    secp256k1_ge_clear(&ctx->offset);
#endif
#endif
    secp256k1_scalar_clear(&ctx->blind);
    secp256k1_gej_clear(&ctx->initial);
    ctx->prec = NULL;
}

static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    secp256k1_ge add;
    secp256k1_ge_storage adds;
    secp256k1_scalar gnb;
    int bits;

#if USE_COMB

    int abs, bit_pos, block, comb_off, index, sign;
#if !COMB_GROUPED
    int bit, tooth;
#endif
    uint32_t recoded[9];
    secp256k1_fe neg;

    memset(&adds, 0, sizeof(adds));
    *r = ctx->initial;

    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    secp256k1_scalar_add(&gnb, gn, &ctx->blind);
    secp256k1_scalar_signed_recoding(recoded, &gnb, COMB_BITS + COMB_OFFSET);

    comb_off = COMB_SPACING - 1;
    for (;;) {
        bit_pos = comb_off;
        for (block = 0; block < COMB_BLOCKS; ++block) {
#if COMB_GROUPED
            bits = recoded[bit_pos >> 5] >> (bit_pos & 0x1F);
            bit_pos += COMB_TEETH;
#else
            bits = 0;
            for (tooth = 0; tooth < COMB_TEETH; ++tooth) {
                bit = recoded[bit_pos >> 5] >> (bit_pos & 0x1F);
                bits &= ~(1 << tooth);
                bits ^= bit << tooth;
                bit_pos += COMB_SPACING;
            }
#endif

            sign = (bits >> (COMB_TEETH - 1)) & 1;
            abs = (bits ^ -sign) & COMB_MASK;

            VERIFY_CHECK(sign == 0 || sign == 1);
            VERIFY_CHECK(0 <= abs && abs < COMB_POINTS);

            for (index = 0; index < COMB_POINTS; ++index) {
                secp256k1_ge_storage_cmov(&adds, &(*ctx->prec)[block][index], index == abs);
            }

            secp256k1_ge_from_storage(&add, &adds);
            secp256k1_fe_negate(&neg, &add.y, 1);
            secp256k1_fe_cmov(&add.y, &neg, sign);

            secp256k1_gej_add_ge(r, r, &add);
        }

        if (--comb_off < 0) {
            break;
        }

        secp256k1_gej_double(r, r);
    }

    secp256k1_fe_clear(&neg);
    memset(recoded, 0, sizeof(recoded));
    abs = 0;
    sign = 0;

#else
    int i, j;
    memset(&adds, 0, sizeof(adds));
    *r = ctx->initial;
    /* Blind scalar/point multiplication by computing (n-b)G + bG instead of nG. */
    secp256k1_scalar_add(&gnb, gn, &ctx->blind);
    add.infinity = 0;
    for (j = 0; j < 64; j++) {
        bits = secp256k1_scalar_get_bits(&gnb, j * 4, 4);
        for (i = 0; i < 16; i++) {
            /** This uses a conditional move to avoid any secret data in array indexes.
             *   _Any_ use of secret indexes has been demonstrated to result in timing
             *   sidechannels, even when the cache-line access patterns are uniform.
             *  See also:
             *   "A word of warning", CHES 2013 Rump Session, by Daniel J. Bernstein and Peter Schwabe
             *    (https://cryptojedi.org/peter/data/chesrump-20130822.pdf) and
             *   "Cache Attacks and Countermeasures: the Case of AES", RSA 2006,
             *    by Dag Arne Osvik, Adi Shamir, and Eran Tromer
             *    (http://www.tau.ac.il/~tromer/papers/cache.pdf)
             */
            secp256k1_ge_storage_cmov(&adds, &(*ctx->prec)[j][i], i == bits);
        }
        secp256k1_ge_from_storage(&add, &adds);
        secp256k1_gej_add_ge(r, r, &add);
    }
#endif
    bits = 0;
    secp256k1_ge_clear(&add);
    memset(&adds, 0, sizeof(adds));
    secp256k1_scalar_clear(&gnb);
}

/* Setup blinding values for secp256k1_ecmult_gen. */
static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
#if USE_COMB
    int spacing;
#endif
    secp256k1_scalar b;
    secp256k1_gej gb;
    secp256k1_fe s;
    unsigned char nonce32[32];
    secp256k1_rfc6979_hmac_sha256 rng;
    int retry;
    unsigned char keydata[64] = {0};
    if (seed32 == NULL) {
        /* When seed is NULL, reset the initial point and blinding value. */
        secp256k1_gej_set_ge(&ctx->initial, &secp256k1_ge_const_g);
        secp256k1_gej_neg(&ctx->initial, &ctx->initial);
        secp256k1_scalar_set_int(&ctx->blind, 1);
#if USE_COMB
        for (spacing = 1; spacing < COMB_SPACING; ++spacing) {
            secp256k1_scalar_add(&ctx->blind, &ctx->blind, &ctx->blind);
        }
#if COMB_OFFSET
        secp256k1_gej_add_ge(&ctx->initial, &ctx->initial, &ctx->offset);
#endif
#endif
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    secp256k1_scalar_get_b32(nonce32, &ctx->blind);
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
    /* Retry for out of range results to achieve uniformity. */
    do {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        retry = !secp256k1_fe_set_b32(&s, nonce32);
        retry |= secp256k1_fe_is_zero(&s);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > Fp. */
    /* Randomize the projection to defend against multiplier sidechannels. */
    secp256k1_gej_rescale(&ctx->initial, &s);
    secp256k1_fe_clear(&s);
    do {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        secp256k1_scalar_set_b32(&b, nonce32, &retry);
        /* A blinding value of 0 works, but would undermine the projection hardening. */
        retry |= secp256k1_scalar_is_zero(&b);
    } while (retry); /* This branch true is cryptographically unreachable. Requires sha256_hmac output > order. */
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    secp256k1_ecmult_gen(ctx, &gb, &b);
    secp256k1_scalar_negate(&b, &b);
    ctx->blind = b;
    ctx->initial = gb;
#if USE_COMB
    for (spacing = 1; spacing < COMB_SPACING; ++spacing) {
        secp256k1_scalar_add(&ctx->blind, &ctx->blind, &ctx->blind);
    }
#if COMB_OFFSET
    secp256k1_gej_add_ge(&ctx->initial, &ctx->initial, &ctx->offset);
#endif
#endif
    secp256k1_scalar_clear(&b);
    secp256k1_gej_clear(&gb);
}

#endif /* SECP256K1_ECMULT_GEN_IMPL_H */
