/***********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_PREC_H
#define SECP256K1_ECMULT_GEN_PREC_H

#include "ecmult_gen.h"

static const size_t ECMULT_GEN_PREC_TABLE_SIZE = ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G * sizeof(secp256k1_ge_storage);

static void secp256k1_ecmult_gen_create_prec_table(secp256k1_ge_storage* table, const secp256k1_ge* gen);

#endif /* SECP256K1_ECMULT_GEN_PREC_H */
