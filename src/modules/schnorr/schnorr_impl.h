/***********************************************************************
 * Copyright (c) 2014-2015 Pieter Wuille                               *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php. *
 ***********************************************************************/

#ifndef _SECP256K1_SCHNORR_IMPL_H_
#define _SECP256K1_SCHNORR_IMPL_H_

#include <string.h>

#include "schnorr.h"
#include "num.h"
#include "field.h"
#include "group.h"
#include "ecmult.h"
#include "ecmult_gen.h"

static void secp256k1_schnorr_ge_get_b32(unsigned char *b32, secp256k1_ge* p) {
    secp256k1_fe_normalize(&p->x);
    secp256k1_fe_get_b32(b32, &p->x);
}

static int secp256k1_schnorr_ge_set_b32(secp256k1_ge* p, const unsigned char *b32) {
    secp256k1_fe x;
    if (!secp256k1_fe_set_b32(&x, b32)) {
        return 0;
    }
    return secp256k1_ge_set_xo_var(p, &x, 0);
}

/** Computes {priv = +/- (scalar)b32; pub = priv * G } with pub.y even. */
static int secp256k1_schnorr_nonces_set_b32(const secp256k1_ecmult_gen_context* ctx, secp256k1_scalar* priv, secp256k1_ge* pub, const unsigned char *b32, const secp256k1_ge* pub_others) {
    int overflow = 0;
    int flip = 0;
    secp256k1_gej gej;

    secp256k1_scalar_set_b32(priv, b32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(priv)) {
        secp256k1_scalar_clear(priv);
        return 0;
    }
    secp256k1_ecmult_gen(ctx, &gej, priv);
    if (secp256k1_gej_is_infinity(&gej)) {
        return 0;
    }
    secp256k1_ge_set_gej(pub, &gej);
    secp256k1_fe_normalize(&pub->y);
    if (secp256k1_fe_is_odd(&pub->y)) {
        /* our R's y coordinate is odd, which is not allowed (see rationale above).
           Force it to be even by negating our nonce. */
        flip++;
        if (pub_others != NULL) {
            secp256k1_gej_neg(&gej, &gej);
        } else {
            secp256k1_ge_neg(pub, pub);
        }
    }
    if (pub_others != NULL) {
        secp256k1_gej_add_ge(&gej, &gej, pub_others);
        secp256k1_ge_set_gej(pub, &gej);
        secp256k1_fe_normalize(&pub->y);
        if (secp256k1_fe_is_odd(&pub->y)) {
            /* The combined R's y coordinate odd, which is not allowed. Force it
               to be even by by negating our nonce (and assuming everyone else
               does the same). */
            flip++;
            secp256k1_ge_neg(pub, pub);
        }
    }
    if (flip & 1) {
        secp256k1_scalar_negate(priv, priv);
    }
    return 1;
}

/** Compute a Schnorr signature given our own nonce, and the sum of everyone's public nonces. */
static int secp256k1_schnorr_sig_sign(unsigned char *sig64, const secp256k1_scalar *key, const secp256k1_scalar *nonce_mine, const secp256k1_ge *pubnonce_all, secp256k1_schnorr_msghash hash, const unsigned char *msg32) {
    secp256k1_ge Ra = *pubnonce_all;
    unsigned char h32[32];
    secp256k1_scalar h, s;
    int overflow;

    if (secp256k1_scalar_is_zero(key)) {
        return 0;
    }
    secp256k1_schnorr_ge_get_b32(sig64, &Ra);
    hash(h32, sig64, msg32);
    overflow = 0;
    secp256k1_scalar_set_b32(&h, h32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&h)) {
        return 0;
    }
    secp256k1_scalar_mul(&s, &h, key);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_add(&s, &s, nonce_mine);
    secp256k1_scalar_get_b32(sig64 + 32, &s);
    return 1;
}

static int secp256k1_schnorr_sig_verify(const secp256k1_ecmult_context* ctx, const unsigned char *sig64, const secp256k1_ge *pubkey, secp256k1_schnorr_msghash hash, const unsigned char *msg32) {
    secp256k1_gej Qj, Rj;
    secp256k1_ge Ra;
    secp256k1_fe Rx;
    secp256k1_scalar h, s;
    unsigned char hh[32];
    int overflow;

    if (secp256k1_ge_is_infinity(pubkey)) {
        return 0;
    }
    hash(hh, sig64, msg32);
    overflow = 0;
    secp256k1_scalar_set_b32(&h, hh, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&h)) {
        return 0;
    }
    overflow = 0;
    secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
    if (overflow) {
        return 0;
    }
    if (!secp256k1_fe_set_b32(&Rx, sig64)) {
        return 0;
    }
    secp256k1_gej_set_ge(&Qj, pubkey);
    secp256k1_ecmult(ctx, &Rj, &Qj, &h, &s);
    if (secp256k1_gej_is_infinity(&Rj)) {
        return 0;
    }
    secp256k1_ge_set_gej_var(&Ra, &Rj);
    secp256k1_fe_normalize_var(&Ra.y);
    if (secp256k1_fe_is_odd(&Ra.y)) {
        return 0;
    }
    return secp256k1_fe_equal_var(&Rx, &Ra.x);
}

static int secp256k1_schnorr_sig_recover(const secp256k1_ecmult_context* ctx, const unsigned char *sig64, secp256k1_ge *pubkey, secp256k1_schnorr_msghash hash, const unsigned char *msg32) {
    secp256k1_gej Qj, Rj;
    secp256k1_ge Ra;
    secp256k1_scalar h, s;
    unsigned char hh[32];
    int overflow;

    hash(hh, sig64, msg32);
    overflow = 0;
    secp256k1_scalar_set_b32(&h, hh, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&h)) {
        return 0;
    }
    overflow = 0;
    secp256k1_scalar_set_b32(&s, sig64 + 32, &overflow);
    if (overflow) {
        return 0;
    }
    if (!secp256k1_schnorr_ge_set_b32(&Ra, sig64)) {
        return 0;
    }
    secp256k1_gej_set_ge(&Rj, &Ra);
    secp256k1_scalar_inverse_var(&h, &h);
    secp256k1_scalar_negate(&s, &s);
    secp256k1_scalar_mul(&s, &s, &h);
    secp256k1_ecmult(ctx, &Qj, &Rj, &h, &s);
    if (secp256k1_gej_is_infinity(&Qj)) {
        return 0;
    }
    secp256k1_ge_set_gej(pubkey, &Qj);
    return 1;
}

static int secp256k1_schnorr_sig_combine(unsigned char *sig64, size_t n, const unsigned char * const *sig64ins) {
    secp256k1_scalar s = SECP256K1_SCALAR_CONST(0, 0, 0, 0, 0, 0, 0, 0);
    size_t i;
    for (i = 0; i < n; i++) {
        secp256k1_scalar si;
        int overflow;
        secp256k1_scalar_set_b32(&si, sig64ins[i] + 32, &overflow);
        if (overflow) {
            return 0;
        }
        if (i) {
            if (memcmp(sig64ins[i - 1], sig64ins[i], 32) != 0) {
                return 0;
            }
        }
        secp256k1_scalar_add(&s, &s, &si);
    }
    if (secp256k1_scalar_is_zero(&s)) {
        return 0;
    }
    memcpy(sig64, sig64ins[0], 32);
    secp256k1_scalar_get_b32(sig64 + 32, &s);
    secp256k1_scalar_clear(&s);
    return 1;
}

#endif
