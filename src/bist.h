/**********************************************************************
 * Copyright (c) 2014, 2015 Gregory Maxwell                           *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_BIST_H_
#define _SECP256K1_BIST_H_

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

void secp256k1_ecdsa_verify_bist(void);
void secp256k1_pubkey_bist(void);

#endif
