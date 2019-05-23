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
    secp256k1_ge prec[1024];
    secp256k1_gej gj;
    secp256k1_gej nums_gej;
    int i, j;
#endif

    if (ctx->prec != NULL) {
        return;
    }
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
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
        secp256k1_ge_set_all_gej_var(prec, precj, 1024);
    }
    for (j = 0; j < 64; j++) {
        for (i = 0; i < 16; i++) {
            secp256k1_ge_to_storage(&(*ctx->prec)[j][i], &prec[j*16 + i]);
        }
    }
    secp256k1_fe_set_int(&ctx->iso, 1);
#else
    (void)cb;
    ctx->prec = (secp256k1_ge_storage (*)[64][16])secp256k1_ecmult_static_context;
#endif

    secp256k1_gej_set_ge(&ctx->initial, &secp256k1_ge_const_g);
    secp256k1_gej_neg(&ctx->initial, &ctx->initial);
    secp256k1_scalar_set_int(&ctx->blind, 1);

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
        dst->prec = (secp256k1_ge_storage (*)[64][16])checked_malloc(cb, sizeof(*dst->prec));
        memcpy(dst->prec, src->prec, sizeof(*dst->prec));
        dst->iso = src->iso;
#else
        (void)cb;
        dst->prec = src->prec;
#endif
        dst->initial = src->initial;
        dst->blind = src->blind;
    }
}

static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context *ctx) {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    free(ctx->prec);
    secp256k1_fe_clear(&ctx->iso);
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
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
    secp256k1_fe_mul(&r->z, &r->z, &ctx->iso);
#endif
    bits = 0;
    secp256k1_ge_clear(&add);
    secp256k1_scalar_clear(&gnb);
}

/* Setup blinding values for secp256k1_ecmult_gen. */
static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    secp256k1_scalar b;
    secp256k1_gej gb;
    secp256k1_fe iso;
    unsigned char nonce32[32];
    secp256k1_rfc6979_hmac_sha256 rng;
    int retry;
#ifdef USE_ECMULT_STATIC_PRECOMPUTATION
    unsigned char keydata[64] = {0};
#else
    secp256k1_ge tmp;
    secp256k1_fe iso2, iso3;
    int i, j;
    unsigned char keydata[96] = {0};
#endif

    /** Initialize the RNG. Using a CSPRNG allows a failure free interface, avoids needing large
     *  amounts of random data, and guards against weak or adversarial seeds.  This is a simpler
     *  and safer interface than asking the caller for blinding values directly and expecting them
     *  to retry on failure. */
    {
        /* The prior blinding values are chained forward by including them in the hash. */
        secp256k1_scalar_get_b32(keydata, &ctx->blind);
#ifdef USE_ECMULT_STATIC_PRECOMPUTATION
        if (seed32 != NULL) {
            memcpy(keydata + 32, seed32, 32);
        }
        secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, seed32 ? 64 : 32);
#else
        secp256k1_fe_get_b32(keydata + 32, &ctx->iso);
        if (seed32 != NULL) {
            memcpy(keydata + 64, seed32, 32);
        }
        secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, seed32 ? 96 : 64);
#endif
        memset(keydata, 0, sizeof(keydata));
    }

    /* Choose a random isomorphism, defined by some non-zero field element. */
    do {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);

        /* Retry for out of range results to achieve uniformity. */
        retry = !secp256k1_fe_set_b32(&iso, nonce32);
        retry |= secp256k1_fe_is_zero(&iso);
    }
    /* This branch true is cryptographically unreachable. Requires sha256_hmac output > Fp. */
    while (retry);

    /* Map precomputed points onto the random isomorphism to defend against multiplier sidechannels. */
    {
#ifdef USE_ECMULT_STATIC_PRECOMPUTATION
        /* For static case, we settle for randomizing the projective coordinate of ctx->initial. */
        secp256k1_gej_rescale(&ctx->initial, &iso);
#else
        secp256k1_fe_sqr(&iso2, &iso);
        secp256k1_fe_mul(&iso3, &iso2, &iso);

        secp256k1_gej_to_iso(&ctx->initial, &iso2, &iso3);

        for (j = 0; j < 64; j++) {
            for (i = 0; i < 16; i++) {
                secp256k1_ge_from_storage(&tmp, &(*ctx->prec)[j][i]);
                secp256k1_ge_to_iso(&tmp, &iso2, &iso3);
                secp256k1_ge_to_storage(&(*ctx->prec)[j][i], &tmp);
            }
        }

        secp256k1_fe_clear(&iso2);
        secp256k1_fe_clear(&iso3);
        secp256k1_ge_clear(&tmp);
#endif
    }

    /* Choose a random scalar 'blind'. */
    do {
        secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
        secp256k1_scalar_set_b32(&b, nonce32, &retry);
        /* A blinding value of 0 works, but would undermine the projection hardening. */
        retry |= secp256k1_scalar_is_zero(&b);
    }
    /* This branch true is cryptographically unreachable. Requires sha256_hmac output > order. */
    while (retry);

    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);

    /* Calculate the 'initial' point corresponding to the chosen scalar 'blind'. */
    {
#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
        secp256k1_fe_mul(&iso, &iso, &ctx->iso);
        secp256k1_fe_set_int(&ctx->iso, 1);
#endif

        secp256k1_ecmult_gen(ctx, &gb, &b);
        secp256k1_scalar_negate(&b, &b);
        ctx->blind = b;
        ctx->initial = gb;

#ifndef USE_ECMULT_STATIC_PRECOMPUTATION
        secp256k1_fe_normalize(&iso);
        ctx->iso = iso;
        secp256k1_fe_clear(&iso);
#endif
    }

    secp256k1_scalar_clear(&b);
    secp256k1_gej_clear(&gb);
}

#endif /* SECP256K1_ECMULT_GEN_IMPL_H */
