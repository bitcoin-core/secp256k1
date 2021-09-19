/***********************************************************************
 * Copyright (c) 2021 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FIELD_REPR_H
#define SECP256K1_FIELD_REPR_H

#include <stdint.h>

typedef struct {
    /* X = sum(i=0..4, n[i]*2^(i*64)) mod p
     * where p = 2^256 - 0x1000003D1
     *
     * Magnitude m implies that n[4] < (magnitude << 34).
     * Normalized implies n[4]==0 and X < p.
     */
    uint64_t n[5];
#ifdef VERIFY
    int magnitude;
    int normalized;
    uint64_t precomputed; /* 64-bit to avoid padding bytes */
#endif
} secp256k1_fe;

/* Unpacks a constant into a overlapping multi-limbed FE element. */
#define SECP256K1_FE_CONST_INNER(d7, d6, d5, d4, d3, d2, d1, d0) { \
    (d0) | (((uint64_t)(d1)) << 32), \
    (d2) | (((uint64_t)(d3)) << 32), \
    (d4) | (((uint64_t)(d5)) << 32), \
    (d6) | (((uint64_t)(d7)) << 32), \
    0 \
}

#ifdef VERIFY
#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0)), 1, 1, 1}
#else
#define SECP256K1_FE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {SECP256K1_FE_CONST_INNER((d7), (d6), (d5), (d4), (d3), (d2), (d1), (d0))}
#endif

typedef struct {
    uint64_t n[4];
} secp256k1_fe_storage;

#define SECP256K1_FE_STORAGE_CONST(d7, d6, d5, d4, d3, d2, d1, d0) {{ \
    (d0) | (((uint64_t)(d1)) << 32), \
    (d2) | (((uint64_t)(d3)) << 32), \
    (d4) | (((uint64_t)(d5)) << 32), \
    (d6) | (((uint64_t)(d7)) << 32) \
}}

#define SECP256K1_FE_STORAGE_CONST_GET(d) \
    (uint32_t)(d.n[3] >> 32), (uint32_t)d.n[3], \
    (uint32_t)(d.n[2] >> 32), (uint32_t)d.n[2], \
    (uint32_t)(d.n[1] >> 32), (uint32_t)d.n[1], \
    (uint32_t)(d.n[0] >> 32), (uint32_t)d.n[0]

#endif /* SECP256K1_FIELD_REPR_H */
