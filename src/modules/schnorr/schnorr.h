/***********************************************************************
 * Copyright (c) 2014-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_MODULE_SCHNORR_H_
#define _SECP256K1_MODULE_SCHNORR_H_

#include "scalar.h"
#include "group.h"

typedef void (*secp256k1_schnorr_msghash)(unsigned char *h32, const unsigned char *r32, const unsigned char *msg32);

/** Compute the private and public nonce to use in signing, based on a 32-byte array and the sum of others' public nonces. */
static int secp256k1_schnorr_nonces_set_b32(const secp256k1_ecmult_gen_context* ctx, secp256k1_scalar* nonce_mine, secp256k1_ge* pubnonce_all, const unsigned char *b32, const secp256k1_ge* pubnonce_others);

/** Compute a Schnorr signature given a private key, your own private nonce, and the sum of everyone's public nonces. */
static int secp256k1_schnorr_sig_sign(unsigned char *sig64, const secp256k1_scalar *key, const secp256k1_scalar* priv_mine, const secp256k1_ge* pub_all, secp256k1_schnorr_msghash hash, const unsigned char *msg32);

/** Verify a Schnorr signature. */
static int secp256k1_schnorr_sig_verify(const secp256k1_ecmult_context* ctx, const unsigned char *sig64, const secp256k1_ge *pubkey, secp256k1_schnorr_msghash hash, const unsigned char *msg32);

/** Recover the public key of the signer of a Schnorr signature, assuming it is valid. */
static int secp256k1_schnorr_sig_recover(const secp256k1_ecmult_context* ctx, const unsigned char *sig64, secp256k1_ge *pubkey, secp256k1_schnorr_msghash hash, const unsigned char *msg32);

/** Combine several partial stage 2 Schnorr signatures. */
static int secp256k1_schnorr_sig_combine(unsigned char *sig64, size_t n, const unsigned char * const *sig64ins);

#endif
