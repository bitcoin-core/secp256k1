/***********************************************************************
 * Copyright (c) 2013-2014 Diederik Huys, Pieter Wuille                *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

/**
 * Changelog:
 * - March 2013, Diederik Huys:    original version
 * - November 2014, Pieter Wuille: updated to use Peter Dettman's parallel
 * multiplication algorithm
 * - December 2014, Pieter Wuille: converted from YASM to GCC inline assembly
 */

#ifndef SECP256K1_FIELD_INNER5X52_IMPL_H
#define SECP256K1_FIELD_INNER5X52_IMPL_H

// #include "dettman.h"
SECP256K1_INLINE static void
secp256k1_fe_mul_inner(uint64_t *r, const uint64_t *a,
                       const uint64_t *SECP256K1_RESTRICT b) {
  fiat_secp256k1_dettman_mul(r, a, b);
}
SECP256K1_INLINE static void secp256k1_fe_sqr_inner(uint64_t *r,
                                                    const uint64_t *a) {
  fiat_secp256k1_dettman_square(r, a);
}

#endif /* SECP256K1_FIELD_INNER5X52_IMPL_H */
