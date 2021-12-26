/***********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

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
    secp256k1_ge_clear(&ctx->ge_offset);
}

/* For accelerating the computation of a*G:
 * To harden against timing attacks, use the following mechanism:
 * * Break up the multiplicand into groups of PREC_BITS bits, called n_0, n_1, n_2, ..., n_(PREC_N-1).
 * * Compute sum(n_i * (PREC_G)^i * G + U_i, i=0 ... PREC_N-1), where:
 *   * U_i = U * 2^i, for i=0 ... PREC_N-2
 *   * U_i = U * (1-2^(PREC_N-1)), for i=PREC_N-1
 *   where U is a point with no known corresponding scalar. Note that sum(U_i, i=0 ... PREC_N-1) = 0.
 * For each i, and each of the PREC_G possible values of n_i, (n_i * (PREC_G)^i * G + U_i) is
 * precomputed (call it prec(i, n_i)). The formula now becomes sum(prec(i, n_i), i=0 ... PREC_N-1).
 * None of the resulting prec group elements have a known scalar, and neither do any of
 * the intermediate sums while computing a*G.
 * The prec values are stored in secp256k1_ecmult_gen_prec_table[i][n_i] = n_i * (PREC_G)^i * G + U_i.
 */
static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context *ctx, secp256k1_gej *r, const secp256k1_scalar *gn) {
    int bits = ECMULT_GEN_PREC_BITS;
    int g = ECMULT_GEN_PREC_G(bits);
    int n = ECMULT_GEN_PREC_N(bits);

    secp256k1_ge add;
    secp256k1_ge_storage adds;
    secp256k1_scalar gnb;
    int i, j, n_i;

    memset(&adds, 0, sizeof(adds));
    secp256k1_gej_set_infinity(r);

    /* Blind scalar/point multiplication by computing (gn-b)*G + b*G instead of gn*G. */
    secp256k1_scalar_add(&gnb, gn, &ctx->scalar_offset);

    for (i = 0; i < n; i++) {
        n_i = secp256k1_scalar_get_bits(&gnb, i * bits, bits);
        for (j = 0; j < g; j++) {
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
            secp256k1_ge_storage_cmov(&adds, &secp256k1_ecmult_gen_prec_table[i][j], j == n_i);
        }
        secp256k1_ge_from_storage(&add, &adds);
        secp256k1_gej_add_ge(r, r, &add);
    }
    n_i = 0;

    /* Correct for the scalar_offset added at the start (ge_offset = b*G, while b was
     * subtracted from the input scalar gn). */
    secp256k1_gej_add_ge(r, r, &ctx->ge_offset);

    secp256k1_ge_clear(&add);
    secp256k1_scalar_clear(&gnb);
}

/* Setup blinding values for secp256k1_ecmult_gen. */
static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32) {
    secp256k1_scalar b;
    secp256k1_gej gb;
    unsigned char nonce32[32];
    secp256k1_rfc6979_hmac_sha256 rng;
    unsigned char keydata[64];
    if (seed32 == NULL) {
        /* When seed is NULL, reset the final point and blinding value. */
        secp256k1_ge_neg(&ctx->ge_offset, &secp256k1_ge_const_g);
        ctx->scalar_offset = secp256k1_scalar_one;
        return;
    }
    /* The prior blinding value (if not reset) is chained forward by including it in the hash. */
    secp256k1_scalar_get_b32(keydata, &ctx->scalar_offset);
    /** Using a CSPRNG allows a failure free interface, avoids needing large amounts of random data,
     *   and guards against weak or adversarial seeds.  This is a simpler and safer interface than
     *   asking the caller for blinding values directly and expecting them to retry on failure.
     */
    VERIFY_CHECK(seed32 != NULL);
    memcpy(keydata + 32, seed32, 32);
    secp256k1_rfc6979_hmac_sha256_initialize(&rng, keydata, 64);
    memset(keydata, 0, sizeof(keydata));

    /* TODO: reintroduce projective blinding. */

    /* For a random blinding value b, set ctx->scalar_offset=-b, ctx->ge_offset=bG. */
    secp256k1_rfc6979_hmac_sha256_generate(&rng, nonce32, 32);
    secp256k1_scalar_set_b32(&b, nonce32, NULL);
    /* The blinding value cannot be zero, as that would mean ge_offset = infinity,
     * which secp256k1_gej_add_ge cannot handle. */
    secp256k1_scalar_cmov(&b, &secp256k1_scalar_one, secp256k1_scalar_is_zero(&b));
    secp256k1_rfc6979_hmac_sha256_finalize(&rng);
    memset(nonce32, 0, 32);
    secp256k1_ecmult_gen(ctx, &gb, &b);
    secp256k1_scalar_negate(&b, &b);
    ctx->scalar_offset = b;
    secp256k1_ge_set_gej(&ctx->ge_offset, &gb);

    /* Clean up. */
    secp256k1_scalar_clear(&b);
    secp256k1_gej_clear(&gb);
}

#endif /* SECP256K1_ECMULT_GEN_IMPL_H */
