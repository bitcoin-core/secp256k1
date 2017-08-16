/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECMULT_CONST_
#define _SECP256K1_ECMULT_CONST_

#include "scalar.h"
#include "group.h"
#ifdef USE_ENDOMORPHISM
    #define WNAF_BITS 128
#else
    #define WNAF_BITS 256
#endif

#define WNAF_SIZE(w) ((WNAF_BITS + (w) - 1) / (w))

static void secp256k1_ecmult_const(secp256k1_gej *r, const secp256k1_ge *a, const secp256k1_scalar *q);
static int secp256k1_wnaf_const(int *wnaf, secp256k1_scalar s, int w);

#endif
