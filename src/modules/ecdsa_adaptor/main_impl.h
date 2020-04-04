/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H

#include "include/secp256k1_ecdsa_adaptor.h"
#include "modules/ecdsa_adaptor/dleq_impl.h"

/* 5. s' = k⁻¹(H(m) + x_coord(R)x) */
int secp256k1_ecdsa_adaptor_sign_helper(secp256k1_scalar *sigs, secp256k1_scalar *message, secp256k1_scalar *k, secp256k1_ge *r, secp256k1_scalar *sk) {
    unsigned char b[32];
    secp256k1_scalar sigr;
    secp256k1_scalar n;
    int overflow;
    int high;

    secp256k1_fe_normalize(&r->x);
    secp256k1_fe_get_b32(b, &r->x);
    secp256k1_scalar_set_b32(&sigr, b, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_scalar_mul(&n, &sigr, sk);
    secp256k1_scalar_add(&n, &n, message);
    secp256k1_scalar_inverse(sigs, k);
    secp256k1_scalar_mul(sigs, sigs, &n);

    secp256k1_scalar_clear(&n);

    high = secp256k1_scalar_is_high(sigs);
    secp256k1_scalar_cond_negate(sigs, high);

    /* TODO: deal with lows */

    return !secp256k1_scalar_is_zero(sigs);
}

int secp256k1_ecdsa_adaptor_sign(const secp256k1_context* ctx, unsigned char *adaptor_sig65, unsigned char *adaptor_proof97, unsigned char *seckey32, const secp256k1_pubkey *adaptor, const unsigned char *msg32) {
    unsigned char nonce32[32];
    secp256k1_scalar k;
    secp256k1_gej rj, rpj;
    secp256k1_ge r, rp;
    secp256k1_ge adaptor_ge;
    secp256k1_scalar dleq_proof_s;
    secp256k1_scalar dleq_proof_e;
    secp256k1_scalar sk;
    secp256k1_scalar msg;
    secp256k1_scalar sp;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(adaptor_sig65 != NULL);
    ARG_CHECK(adaptor_proof97 != NULL);
    ARG_CHECK(adaptor != NULL);
    ARG_CHECK(msg32 != NULL);

    /* 1. Choose k randomly, R' = k*G */
    /* TODO: include adaptor, fix msg32 */
    if (!nonce_function_bip340(nonce32, msg32, seckey32, msg32, (unsigned char *)"ecdsaadaptorsig", NULL, 0)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&k, nonce32, NULL);
    if (secp256k1_scalar_is_zero(&k)) {
        return 0;
    }
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rpj, &k);

    if (!secp256k1_pubkey_load(ctx, &adaptor_ge, adaptor)) {
        return 0;
    }
    /* 2. R = k*Y; */
    secp256k1_ecmult_const(&rj, &adaptor_ge, &k, 256);

    /* 4. [sic] proof = DLEQ_prove((G,R'),(Y, R)) */
    secp256k1_dleq_proof(&ctx->ecmult_gen_ctx, &dleq_proof_s, &dleq_proof_e, (unsigned char *)"ecdsaadaptorsig", &k, &adaptor_ge);

    /* 5. s' = k⁻¹(H(m) + x_coord(R)x) */
    secp256k1_ge_set_gej(&r, &rj);
    secp256k1_scalar_set_b32(&sk, seckey32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&sk)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&msg, msg32, NULL);
    if(!secp256k1_ecdsa_adaptor_sign_helper(&sp, &msg, &k, &r, &sk)) {
        return 0;
    }

    /* 6. return (R, R', s', proof) */
    secp256k1_dleq_serialize_point(adaptor_proof97, &rp);
    secp256k1_scalar_get_b32(&adaptor_proof97[33], &dleq_proof_s);
    secp256k1_scalar_get_b32(&adaptor_proof97[33+32], &dleq_proof_e);

    secp256k1_dleq_serialize_point(adaptor_sig65, &r);
    secp256k1_scalar_get_b32(&adaptor_sig65[33], &sp);

    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);
    return 1;
}

#endif /* SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H */
