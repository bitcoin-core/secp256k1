/***********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_PREC_H
#define SECP256K1_ECMULT_GEN_PREC_H

#include "ecmult_gen.h"

static const size_t ECMULT_GEN_PREC_TABLE_SIZE = ROUND_TO_ALIGN(sizeof(*((secp256k1_ecmult_gen_context*) NULL)->prec));

static void secp256k1_ecmult_gen_create_prec_table(secp256k1_ecmult_gen_context *ctx, void **prealloc);

#endif /* SECP256K1_ECMULT_GEN_PREC_H */
