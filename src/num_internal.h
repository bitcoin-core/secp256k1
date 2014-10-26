// Copyright (c) 2014 Cory Fields
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SECP256K1_NUM_REPR_
#define _SECP256K1_NUM_REPR_

#include <inttypes.h>

// TODO: Once gmp is no longer needed, experiment with limb size here.
//typedef uintmax_t bn_limb;

typedef unsigned long bn_limb;
#define INT_NUM_BITS (sizeof(bn_limb)*8)
#define NUM_LIMBS ((256+INT_NUM_BITS-1)/INT_NUM_BITS)
#define SHIFT_SIZE (INT_NUM_BITS / 2)
#define SHIFT_MASK (ULONG_MAX >> SHIFT_SIZE)

typedef struct {
  bn_limb data[2*NUM_LIMBS];
  int neg;
  int limbs;
} secp256k1_num_t;

#endif
