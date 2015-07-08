/**********************************************************************
 * Copyright (c) 2015 Pieter Wuille, Andrew Poelstra                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_ECDH_
#define _SECP256K1_ECDH_

#include "scalar.h"
#include "group.h"

static void secp256k1_point_multiply(secp256k1_gej_t *r, const secp256k1_ge_t *a, const secp256k1_scalar_t *q);

#endif
