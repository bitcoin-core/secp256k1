/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_TESTRAND_IMPL_H_
#define _SECP256K1_TESTRAND_IMPL_H_

#include <stdint.h>
#include <string.h>

#include "testrand.h"

SECP256K1_INLINE static void secp256k1_rand_seed(secp256k1_rand_t *state, uint64_t v) {
    state->Rz = v >> 32;
    state->Rw = v;

    /* There are two seeds with short (length 1) cycles for the Rz PRNG. */
    if (state->Rz == 0 || state->Rz == 0x9068ffffU) {
        state->Rz = 111;
    }
    /* There are four seeds with short (length 1) cycles for the Rw PRNG. */
    if (state->Rw == 0 || state->Rw == 0x464fffffU ||
         state->Rw == 0x8c9ffffeU || state->Rw == 0xd2effffdU) {
        state->Rw = 111;
    }
}

SECP256K1_INLINE static uint32_t secp256k1_rand32(secp256k1_rand_t *state) {
    /* MWC PRNG for tests. */
    state->Rz = 36969 * (state->Rz & 0xFFFF) + (state->Rz >> 16);
    state->Rw = 18000 * (state->Rw & 0xFFFF) + (state->Rw >> 16);
    return (state->Rw << 16) + (state->Rw >> 16) + state->Rz;
}

static void secp256k1_rand256(secp256k1_rand_t *state, unsigned char *b32) {
    int i;
    for (i = 0; i < 8; i++) {
        uint32_t r = secp256k1_rand32(state);
        b32[i*4 + 0] = (r >>  0) & 0xFF;
        b32[i*4 + 1] = (r >>  8) & 0xFF;
        b32[i*4 + 2] = (r >> 16) & 0xFF;
        b32[i*4 + 3] = (r >> 24) & 0xFF;
    }
}

static void secp256k1_rand256_test(secp256k1_rand_t *state, unsigned char *b32) {
    int bits=0;
    memset(b32, 0, 32);
    while (bits < 256) {
        uint32_t ent = secp256k1_rand32(state);
        int now = 1 + ((ent % 64)*((ent >> 6) % 32)+16)/31;
        uint32_t val = 1 & (ent >> 11);
        while (now > 0 && bits < 256) {
            b32[bits / 8] |= val << (bits % 8);
            now--;
            bits++;
        }
    }
}

#endif
