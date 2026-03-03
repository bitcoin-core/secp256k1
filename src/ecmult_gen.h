/***********************************************************************
 * Copyright (c) Pieter Wuille, Peter Dettman                          *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_H
#define SECP256K1_ECMULT_GEN_H

#include "scalar.h"
#include "group.h"


/* Configuration parameters for the signed-digit multi-comb algorithm:
 *
 * - SECP256K1_COMB_BLOCKS is the number of blocks the input is split into. Each
 *   has a corresponding table.
 * - SECP256K1_COMB_TEETH is the number of bits simultaneously covered by one table.
 * - COMB_RANGE is the number of bits in supported scalars. For production
 *   purposes, only 256 is reasonable, but smaller numbers are supported for
 *   exhaustive test mode.
 *
 * The comb's spacing (COMB_SPACING), or the distance between the teeth,
 * is defined as ceil(COMB_RANGE / (SECP256K1_COMB_BLOCKS * SECP256K1_COMB_TEETH)). Each block covers
 * COMB_SPACING * SECP256K1_COMB_TEETH consecutive bits in the input.
 *
 * The size of the precomputed table is SECP256K1_COMB_BLOCKS * (1 << (SECP256K1_COMB_TEETH - 1))
 * secp256k1_ge_storages.
 *
 * The number of point additions equals SECP256K1_COMB_BLOCKS * COMB_SPACING. Each point
 * addition involves a cmov from (1 << (SECP256K1_COMB_TEETH - 1)) table entries and a
 * conditional negation.
 *
 * The number of point doublings is COMB_SPACING - 1. */

#if defined(SECP256K1_EXHAUSTIVE_TEST_ORDER)
/* We need to control these values for exhaustive tests because
 * the table cannot have infinities in them (secp256k1_ge_storage
 * doesn't support infinities) */
#  undef SECP256K1_COMB_BLOCKS
#  undef SECP256K1_COMB_TEETH
#  if SECP256K1_EXHAUSTIVE_TEST_ORDER == 7
#    define COMB_RANGE 3
#    define SECP256K1_COMB_BLOCKS 1
#    define SECP256K1_COMB_TEETH 2
#  elif SECP256K1_EXHAUSTIVE_TEST_ORDER == 13
#    define COMB_RANGE 4
#    define SECP256K1_COMB_BLOCKS 1
#    define SECP256K1_COMB_TEETH 2
#  elif SECP256K1_EXHAUSTIVE_TEST_ORDER == 199
#    define COMB_RANGE 8
#    define SECP256K1_COMB_BLOCKS 2
#    define SECP256K1_COMB_TEETH 3
#  else
#    error "Unknown exhaustive test order"
#  endif
#  if (COMB_RANGE >= 32) || ((SECP256K1_EXHAUSTIVE_TEST_ORDER >> (COMB_RANGE - 1)) != 1)
#    error "COMB_RANGE != ceil(log2(SECP256K1_EXHAUSTIVE_TEST_ORDER+1))"
#  endif
#else /* !defined(SECP256K1_EXHAUSTIVE_TEST_ORDER) */
#  define COMB_RANGE 256
#endif /* defined(SECP256K1_EXHAUSTIVE_TEST_ORDER) */

/* Use (11, 6) as default configuration, which results in a 22 kB table. */
#ifndef SECP256K1_COMB_BLOCKS
#  define SECP256K1_COMB_BLOCKS 11
#  ifdef SECP256K1_DEBUG_CONFIG
#    pragma message DEBUG_CONFIG_MSG("SECP256K1_COMB_BLOCKS undefined, assuming default value")
#  endif
#endif
#ifndef SECP256K1_COMB_TEETH
#  define SECP256K1_COMB_TEETH 6
#  ifdef SECP256K1_DEBUG_CONFIG
#    pragma message DEBUG_CONFIG_MSG("SECP256K1_COMB_TEETH undefined, assuming default value")
#  endif
#endif
/* Use ceil(COMB_RANGE / (SECP256K1_COMB_BLOCKS * SECP256K1_COMB_TEETH)) as COMB_SPACING. */
#define COMB_SPACING CEIL_DIV(COMB_RANGE, SECP256K1_COMB_BLOCKS * SECP256K1_COMB_TEETH)

/* Range checks on the parameters. */

/* The remaining COMB_* parameters are derived values, don't modify these. */
/* - The number of bits covered by all the blocks; must be at least COMB_RANGE. */
#define COMB_BITS (SECP256K1_COMB_BLOCKS * SECP256K1_COMB_TEETH * COMB_SPACING)
/* - The number of entries per table. */
#define COMB_POINTS (1 << (SECP256K1_COMB_TEETH - 1))

/* Sanity checks. */
#if !(1 <= SECP256K1_COMB_BLOCKS && SECP256K1_COMB_BLOCKS <= 256)
#  error "SECP256K1_COMB_BLOCKS must be in the range [1, 256]"
#endif
#if !(1 <= SECP256K1_COMB_TEETH && SECP256K1_COMB_TEETH <= 8)
#  error "SECP256K1_COMB_TEETH must be in the range [1, 8]"
#endif
#if COMB_BITS < COMB_RANGE
#  error "SECP256K1_COMB_BLOCKS * SECP256K1_COMB_TEETH * COMB_SPACING is too low"
#endif

/* These last 2 checks are not strictly required, but prevent gratuitously inefficient
 * configurations. Note that they compare with 256 rather than COMB_RANGE, so they do
 * permit somewhat excessive values for the exhaustive test case, where testing with
 * suboptimal parameters may be desirable. */
#if (SECP256K1_COMB_BLOCKS - 1) * SECP256K1_COMB_TEETH * COMB_SPACING >= 256
#  error "SECP256K1_COMB_BLOCKS can be reduced"
#endif
#if SECP256K1_COMB_BLOCKS * (SECP256K1_COMB_TEETH - 1) * COMB_SPACING >= 256
#  error "SECP256K1_COMB_TEETH can be reduced"
#endif

#ifdef SECP256K1_DEBUG_CONFIG
#  pragma message DEBUG_CONFIG_DEF(COMB_RANGE)
#  pragma message DEBUG_CONFIG_DEF(SECP256K1_COMB_BLOCKS)
#  pragma message DEBUG_CONFIG_DEF(SECP256K1_COMB_TEETH)
#  pragma message DEBUG_CONFIG_DEF(COMB_SPACING)
#endif

typedef struct {
    /* Whether the context has been built. */
    int built;

    /* Values chosen such that
     *
     *   n*G == comb(n + scalar_offset, G/2) + ge_offset.
     *
     * This expression lets us use scalar blinding and optimize the comb precomputation. See
     * ecmult_gen_impl.h for more details. */
    secp256k1_scalar scalar_offset;
    secp256k1_ge ge_offset;

    /* Factor used for projective blinding. This value is used to rescale the Z
     * coordinate of the first table lookup. */
    secp256k1_fe proj_blind;
} secp256k1_ecmult_gen_context;

static void secp256k1_ecmult_gen_context_build(secp256k1_ecmult_gen_context* ctx);
static void secp256k1_ecmult_gen_context_clear(secp256k1_ecmult_gen_context* ctx);

/** Multiply with the generator: R = a*G */
static void secp256k1_ecmult_gen(const secp256k1_ecmult_gen_context* ctx, secp256k1_gej *r, const secp256k1_scalar *a);

static void secp256k1_ecmult_gen_blind(secp256k1_ecmult_gen_context *ctx, const unsigned char *seed32);

#endif /* SECP256K1_ECMULT_GEN_H */
