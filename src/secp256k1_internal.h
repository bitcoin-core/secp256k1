/***********************************************************************
 * Copyright (c) 2013-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SECP256K1_INTERNAL_H
#define SECP256K1_SECP256K1_INTERNAL_H

#include "../include/secp256k1.h"

#include "ecmult_gen.h"
#include "group.h"
#include "scalar.h"
#include "util.h"

/* Helper function that determines if a context is proper, i.e., is not the static context or a copy thereof.
 *
 * This is intended for "context" functions such as secp256k1_context_clone. Functions that need specific
 * features of a context should still check for these features directly. For example, a function that needs
 * ecmult_gen should directly check for the existence of the ecmult_gen context. */
static int secp256k1_context_is_proper(const secp256k1_context* ctx);

/* Mark memory as no-longer-secret for the purpose of analysing constant-time behaviour
 *  of the software.
 */
static SECP256K1_INLINE void secp256k1_declassify(const secp256k1_context* ctx, const void *p, size_t len);

static int secp256k1_pubkey_load(const secp256k1_context* ctx, secp256k1_ge* ge, const secp256k1_pubkey* pubkey);
static void secp256k1_pubkey_save(secp256k1_pubkey* pubkey, secp256k1_ge* ge);

static int secp256k1_ec_pubkey_sort_cmp(const void* pk1, const void* pk2, void *ctx);

static void secp256k1_ecdsa_signature_load(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, const secp256k1_ecdsa_signature* sig);
static void secp256k1_ecdsa_signature_save(secp256k1_ecdsa_signature* sig, const secp256k1_scalar* r, const secp256k1_scalar* s);

static int secp256k1_ecdsa_sign_inner(const secp256k1_context* ctx, secp256k1_scalar* r, secp256k1_scalar* s, int* recid, const unsigned char *msg32, const unsigned char *seckey, secp256k1_nonce_function noncefp, const void* noncedata);

static int secp256k1_ec_pubkey_create_helper(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_scalar *seckey_scalar, secp256k1_ge *p, const unsigned char *seckey);
static int secp256k1_ec_seckey_tweak_add_helper(secp256k1_scalar *sec, const unsigned char *tweak32);
static int secp256k1_ec_pubkey_tweak_add_helper(secp256k1_ge *p, const unsigned char *tweak32);

#endif /* SECP256K1_SECP256K1_INTERNAL_H */
