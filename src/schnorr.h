// Copyright (c) 2014 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SECP256K1_SCHNORR_
#define _SECP256K1_SCHNORR_

#include "scalar.h"
#include "group.h"

typedef void (*secp256k1_schnorr_msghash_t)(unsigned char *h32, const unsigned char *r32, const void* data);

static int secp256k1_schnorr_sig_sign(unsigned char *sig64, const secp256k1_scalar_t *key, const secp256k1_scalar_t *nonce, const secp256k1_gej_t *all_nonces, secp256k1_schnorr_msghash_t hash, const void *msg);
static int secp256k1_schnorr_sig_combine(unsigned char *sig64, const unsigned char *sig64a, const unsigned char *sig64b);
static int secp256k1_schnorr_sig_verify(const unsigned char *sig64, const secp256k1_ge_t *pubkey, secp256k1_schnorr_msghash_t hash, const void *msg);

#endif
