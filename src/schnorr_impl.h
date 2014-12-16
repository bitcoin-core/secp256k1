// Copyright (c) 2014 Pieter Wuille
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SECP256K1_SCHNORR_IMPL_H_
#define _SECP256K1_SCHNORR_IMPL_H_

#include <string.h>

#include "schnorr.h"

#include "num.h"
#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static int secp256k1_schnorr_sig_sign(unsigned char *sig64, const secp256k1_scalar_t *key, const secp256k1_scalar_t *nonce, const secp256k1_gej_t *all_nonces, secp256k1_schnorr_msghash_t hash, const void *msg) {
    if (secp256k1_scalar_is_zero(key) || secp256k1_scalar_is_zero(nonce)) {
        return 0;
    }
    secp256k1_fe_t Rx;
    secp256k1_gej_get_x(&Rx, all_nonces);
    secp256k1_fe_normalize(&Rx);
    secp256k1_fe_get_b32(sig64, &Rx);
    unsigned char h[32];
    hash(h, sig64, msg);
    secp256k1_scalar_t s;
    secp256k1_scalar_set_b32(&s, h, NULL);
    secp256k1_scalar_mul(&s, &s, key);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_add(&s, &s, nonce);
    secp256k1_scalar_get_b32(sig64 + 32, &s);
    return 1;
}

static int secp256k1_schnorr_sig_combine(unsigned char *sig64, const unsigned char *sig64a, const unsigned char *sig64b) {
    if (memcmp(sig64a, sig64b, 32) != 0) {
        return 0;
    }
    memcpy(sig64, sig64a, 32);
    secp256k1_scalar_t s1;
    secp256k1_scalar_t s2;
    int overflow1 = 0, overflow2 = 0;
    secp256k1_scalar_set_b32(&s1, sig64a + 32, &overflow1);
    secp256k1_scalar_set_b32(&s2, sig64b + 32, &overflow2);
    secp256k1_scalar_add(&s1, &s1, &s2);
    secp256k1_scalar_get_b32(sig64 + 32, &s1);
    return !overflow1 && !overflow2;
}

static int secp256k1_schnorr_sig_verify(const unsigned char *sig64, const secp256k1_ge_t *pubkey, secp256k1_schnorr_msghash_t hash, const void *msg) {
    unsigned char h[32];
    hash(h, sig64, msg);
    secp256k1_scalar_t H;
    secp256k1_scalar_set_b32(&H, h, NULL);
    secp256k1_scalar_t s;
    int overflow = 0;
    secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_gej_t Q;
    secp256k1_gej_set_ge(&Q, pubkey);
    secp256k1_gej_t r;
    secp256k1_ecmult(&r, &Q, &H, &s);
    if (secp256k1_gej_is_infinity(&r)) {
        return 0;
    }
    secp256k1_fe_t rx;
    secp256k1_gej_get_x_var(&rx, &r);
    secp256k1_fe_normalize(&rx);
    unsigned char R[32];
    secp256k1_fe_get_b32(R, &rx);
    return memcmp(R, sig64, 32) == 0;
}

#endif
