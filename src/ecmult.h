/***********************************************************************
 * Copyright (c) 2013, 2014, 2017 Pieter Wuille, Andrew Poelstra       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_H
#define SECP256K1_ECMULT_H

#include "group.h"
#include "scalar.h"

#ifndef ECMULT_WINDOW_SIZE
#  define ECMULT_WINDOW_SIZE 15
#  ifdef DEBUG_CONFIG
#     pragma message DEBUG_CONFIG_MSG("ECMULT_WINDOW_SIZE undefined, assuming default value")
#  endif
#endif

#ifdef DEBUG_CONFIG
#  pragma message DEBUG_CONFIG_DEF(ECMULT_WINDOW_SIZE)
#endif

/* No one will ever need more than a window size of 24. The code might
 * be correct for larger values of ECMULT_WINDOW_SIZE but this is not
 * tested.
 *
 * The following limitations are known, and there are probably more:
 * If WINDOW_G > 27 and size_t has 32 bits, then the code is incorrect
 * because the size of the memory object that we allocate (in bytes)
 * will not fit in a size_t.
 * If WINDOW_G > 31 and int has 32 bits, then the code is incorrect
 * because certain expressions will overflow.
 */
#if ECMULT_WINDOW_SIZE < 2 || ECMULT_WINDOW_SIZE > 24
#  error Set ECMULT_WINDOW_SIZE to an integer in range [2..24].
#endif

/** The number of entries a table with precomputed multiples needs to have. */
#define ECMULT_TABLE_SIZE(w) ((size_t)1 << ((w)-2))

/** Double multiply: R = na*A + ng*G */
static void secp256k1_ecmult(secp256k1_gej *r, const secp256k1_gej *a, const secp256k1_scalar *na, const secp256k1_scalar *ng);

/**
 * Algorithm identifiers for multi-scalar multiplication.
 *
 * TRIVIAL:      Simple algorithm, no extra memory needed
 * STRAUSS:      Strauss algorithm (efficient for small batches)
 * PIPPENGER_n:  Pippenger algorithm with bucket window size n
 */
typedef enum {
    SECP256K1_ECMULT_MULTI_ALGO_TRIVIAL = 0,
    SECP256K1_ECMULT_MULTI_ALGO_STRAUSS = 1,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_1 = 2,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_2 = 3,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_3 = 4,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_4 = 5,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_5 = 6,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_6 = 7,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_7 = 8,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_8 = 9,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_9 = 10,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_10 = 11,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_11 = 12,
    SECP256K1_ECMULT_MULTI_ALGO_PIPPENGER_12 = 13
} secp256k1_ecmult_multi_algo;

#define SECP256K1_ECMULT_MULTI_NUM_ALGOS 14

/**
 * Calculate max batch size for a given memory limit.
 *
 * For each algorithm, memory usage is modeled as m(x) = A*x + B and
 * running time as c(x) = C*x + D, where x is the batch size. This
 * function finds the algorithm that minimizes time per operation
 * C + D/x at the maximum batch size x = (mem_limit - B) / A.
 *
 * Returns: The optimal batch size, or 0 if memory is insufficient.
 */
static size_t secp256k1_ecmult_multi_batch_size(size_t mem_limit);

/**
 * Select the best algorithm for a given batch size within the memory
 * limit.
 *
 * Among algorithms that fit within mem_limit for the given batch_size,
 * selects the one that minimizes time per operation C + D/batch_size.
 *
 * Returns: The optimal algorithm identifier.
 */
static secp256k1_ecmult_multi_algo secp256k1_ecmult_multi_select(
    size_t mem_limit,
    size_t batch_size
);

/**
 * Multi-multiply: R = scalar_g * G + sum_i scalars[i] * points[i].
 *
 * Chooses the right algorithm for the given number of points.
 *
 * Returns: 1 on success, 0 on memory allocation failure.
 */
static int secp256k1_ecmult_multi(
    const secp256k1_callback *error_callback,
    secp256k1_gej *r,
    size_t n_points,
    const secp256k1_ge *points,
    const secp256k1_scalar *scalars,
    const secp256k1_scalar *scalar_g,
    size_t mem_limit
);

/* Only for benchmarks and testing */
static int secp256k1_ecmult_multi_internal(
    const secp256k1_callback *error_callback,
    secp256k1_ecmult_multi_algo algo,
    secp256k1_gej *r,
    size_t n_points,
    const secp256k1_ge *points,
    const secp256k1_scalar *scalars,
    const secp256k1_scalar *scalar_g
);

#endif /* SECP256K1_ECMULT_H */
