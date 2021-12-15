/*****************************************************************************************************
 * Copyright (c) 2013, 2014, 2017, 2021 Pieter Wuille, Andrew Poelstra, Jonas Nick, Russell O'Connor *
 * Distributed under the MIT software license, see the accompanying                                  *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.                              *
 *****************************************************************************************************/

#ifndef SECP256K1_ECMULT_PREC_H
#define SECP256K1_ECMULT_PREC_H

#include "ecmult.h"

static void secp256k1_ecmult_create_prec_table(secp256k1_ge_storage* table, int window_g, const secp256k1_gej* gen);
static void secp256k1_ecmult_create_prec_two_tables(secp256k1_ge_storage* table, secp256k1_ge_storage* table_128, int window_g, const secp256k1_ge* gen);

#endif /* SECP256K1_ECMULT_PREC_H */
