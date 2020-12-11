/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H

#include "include/secp256k1_ecdsa_adaptor.h"
#include "modules/ecdsa_adaptor/dleq_impl.h"

static void secp256k1_ecdsa_adaptor_sig_serialize(unsigned char *adaptor_sig162, secp256k1_ge *r, secp256k1_ge *rp, const secp256k1_scalar *sp, const secp256k1_scalar *dleq_proof_e, const secp256k1_scalar *dleq_proof_s) {
    size_t size = 33;

    secp256k1_eckey_pubkey_serialize(r, adaptor_sig162, &size, 1);
    secp256k1_eckey_pubkey_serialize(rp, &adaptor_sig162[33], &size, 1);
    secp256k1_scalar_get_b32(&adaptor_sig162[66], sp);
    secp256k1_scalar_get_b32(&adaptor_sig162[98], dleq_proof_e);
    secp256k1_scalar_get_b32(&adaptor_sig162[130], dleq_proof_s);
}

static int secp256k1_ecdsa_adaptor_sig_deserialize(secp256k1_ge *r, secp256k1_scalar *sigr, secp256k1_ge *rp, secp256k1_scalar *sp, secp256k1_scalar *dleq_proof_e, secp256k1_scalar *dleq_proof_s, const unsigned char *adaptor_sig162) {
    /* Ensure that whenever you call this function to deserialize r you also
     * check that X fits into a sigr */
    VERIFY_CHECK((r == NULL) || (r != NULL && sigr != NULL));
    if (r != NULL) {
        if (!secp256k1_eckey_pubkey_parse(r, &adaptor_sig162[0], 33)) {
            return 0;
        }
    }
    if (sigr != NULL) {
        int overflow;
        secp256k1_scalar_set_b32(sigr, &adaptor_sig162[1], &overflow);
        if(overflow) {
            return 0;
        }
    }
    if (rp != NULL) {
        if (!secp256k1_eckey_pubkey_parse(rp, &adaptor_sig162[33], 33)) {
            return 0;
        }
    }
    if (sp != NULL) {
        int overflow;
        secp256k1_scalar_set_b32(sp, &adaptor_sig162[66], &overflow);
        if(overflow) {
            return 0;
        }
    }
    if (dleq_proof_e != NULL) {
        int overflow;
        secp256k1_scalar_set_b32(dleq_proof_e, &adaptor_sig162[98], &overflow);
        if (overflow) {
            return 0;
        }
    }
    if (dleq_proof_s != NULL) {
        int overflow;
        secp256k1_scalar_set_b32(dleq_proof_s, &adaptor_sig162[130], &overflow);
        if (overflow) {
            return 0;
        }
    }
    return 1;
}

int secp256k1_ecdsa_adaptor_fe_to_scalar(secp256k1_scalar *s, const secp256k1_fe *fe) {
    unsigned char b[32];
    int overflow;

    secp256k1_fe_get_b32(b, fe);
    secp256k1_scalar_set_b32(s, b, &overflow);
    return !overflow;
}

/* 5. s' = k⁻¹(H(m) + x_coord(R)x) */
int secp256k1_ecdsa_adaptor_sign_helper(secp256k1_scalar *sigs, secp256k1_scalar *message, secp256k1_scalar *k, secp256k1_ge *r, secp256k1_scalar *sk) {
    secp256k1_scalar sigr;
    secp256k1_scalar n;

    secp256k1_fe_normalize(&r->x);
    if (!secp256k1_ecdsa_adaptor_fe_to_scalar(&sigr, &r->x)) {
        return 0;
    }
    secp256k1_scalar_mul(&n, &sigr, sk);
    secp256k1_scalar_add(&n, &n, message);
    secp256k1_scalar_inverse(sigs, k);
    secp256k1_scalar_mul(sigs, sigs, &n);

    secp256k1_scalar_clear(&n);
    return !secp256k1_scalar_is_zero(sigs);
}

int secp256k1_ecdsa_adaptor_sign(const secp256k1_context* ctx, unsigned char *adaptor_sig162, unsigned char *seckey32, const secp256k1_pubkey *adaptor, const unsigned char *msg32) {
    unsigned char nonce32[32];
    unsigned char buf33[33];
    secp256k1_sha256 sha;
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
    size_t size = 33;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(adaptor != NULL);
    ARG_CHECK(msg32 != NULL);

    /* 1. Choose k randomly, R' = k*G */
    /* Include msg32 and adaptor in nonce derivation */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, msg32, 32);
    if (!secp256k1_pubkey_load(ctx, &adaptor_ge, adaptor)) {
        return 0;
    }
    secp256k1_eckey_pubkey_serialize(&adaptor_ge, buf33, &size, 1);
    secp256k1_sha256_write(&sha, buf33, 33);
    secp256k1_sha256_finalize(&sha, buf33);
    if (!nonce_function_dleq(nonce32, buf33, seckey32, (unsigned char *)"ECDSAAdaptorNon")) {
        return 0;
    }
    secp256k1_scalar_set_b32(&k, nonce32, NULL);
    if (secp256k1_scalar_is_zero(&k)) {
        return 0;
    }
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rpj, &k);

    /* 2. R = k*Y; */
    secp256k1_ecmult_const(&rj, &adaptor_ge, &k, 256);

    /* 4. [sic] proof = DLEQ_prove((G,R'),(Y, R)) */
    if (!secp256k1_dleq_proof(&ctx->ecmult_gen_ctx, &dleq_proof_s, &dleq_proof_e, (unsigned char *)"eq(DLG(secp256k1),DL(secp256k1))", &k, &adaptor_ge)) {
        return 0;
    }

    /* 5. s' = k⁻¹(H(m) + x_coord(R)x) */
    secp256k1_ge_set_gej(&r, &rj);
    secp256k1_scalar_set_b32(&sk, seckey32, &overflow);
    if (overflow || secp256k1_scalar_is_zero(&sk)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&msg, msg32, NULL);
    if(!secp256k1_ecdsa_adaptor_sign_helper(&sp, &msg, &k, &r, &sk)) {
        secp256k1_scalar_clear(&k);
        secp256k1_scalar_clear(&sk);
        return 0;
    }

    /* 6. return (R, R', s', proof) */
    secp256k1_ge_set_gej(&rp, &rpj);
    secp256k1_ecdsa_adaptor_sig_serialize(adaptor_sig162, &r, &rp, &sp, &dleq_proof_e, &dleq_proof_s);

    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);
    return 1;
}

SECP256K1_API int secp256k1_ecdsa_adaptor_sig_verify_helper(const secp256k1_context* ctx, secp256k1_ge *result, secp256k1_scalar *sigr, secp256k1_scalar *sigs, const secp256k1_ge *pubkey, const secp256k1_scalar *message) {
    secp256k1_scalar sn, u1, u2;
    secp256k1_gej pubkeyj;
    secp256k1_gej pr;

    if (secp256k1_scalar_is_zero(sigr) || secp256k1_scalar_is_zero(sigs)) {
        return 0;
    }

    secp256k1_scalar_inverse_var(&sn, sigs);
    secp256k1_scalar_mul(&u1, &sn, message);
    secp256k1_scalar_mul(&u2, &sn, sigr);

    secp256k1_gej_set_ge(&pubkeyj, pubkey);
    secp256k1_ecmult(&ctx->ecmult_ctx, &pr, &pubkeyj, &u2, &u1);
    if (secp256k1_gej_is_infinity(&pr)) {
        return 0;
    }
    secp256k1_ge_set_gej(result, &pr);
    return 1;
}

int secp256k1_ecdsa_adaptor_sig_verify(const secp256k1_context* ctx, const unsigned char *adaptor_sig162, const secp256k1_pubkey *pubkey, const unsigned char *msg32, const secp256k1_pubkey *adaptor) {
    secp256k1_scalar dleq_proof_s, dleq_proof_e;
    secp256k1_scalar msg;
    secp256k1_ge q;
    secp256k1_ge r, rp;
    secp256k1_scalar sp;
    secp256k1_scalar sigr;
    secp256k1_ge adaptor_ge;
    secp256k1_ge rhs;
    secp256k1_gej lhs;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_context_is_built(&ctx->ecmult_ctx));
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(adaptor != NULL);

    /* 1. DLEQ_verify((G,R'),(Y, R)) */
    if (!secp256k1_ecdsa_adaptor_sig_deserialize(&r, &sigr, &rp, &sp, &dleq_proof_e, &dleq_proof_s, adaptor_sig162)) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &adaptor_ge, adaptor)) {
        return 0;
    }
    if(!secp256k1_dleq_verify(&ctx->ecmult_ctx, (unsigned char *)"eq(DLG(secp256k1),DL(secp256k1))", &dleq_proof_s, &dleq_proof_e, &rp, &adaptor_ge, &r)) {
        return 0;
    }

    /* 2. return x_coord(R') == x_coord(s'⁻¹(H(m) * G + x_coord(R) * X)) */
    secp256k1_scalar_set_b32(&msg, msg32, NULL);
    if (!secp256k1_pubkey_load(ctx, &q, pubkey)) {
        return 0;
    }
    if (!secp256k1_ecdsa_adaptor_sig_verify_helper(ctx, &rhs, &sigr, &sp, &q, &msg)) {
        return 0;
    }

    secp256k1_gej_set_ge(&lhs, &rp);
    secp256k1_ge_neg(&rhs, &rhs);
    secp256k1_gej_add_ge_var(&lhs, &lhs, &rhs, NULL);
    return secp256k1_gej_is_infinity(&lhs);
}

int secp256k1_ecdsa_adaptor_adapt(const secp256k1_context* ctx, secp256k1_ecdsa_signature *sig, const unsigned char *adaptor_secret32, const unsigned char *adaptor_sig192) {
    secp256k1_scalar adaptor_secret;
    secp256k1_scalar sp;
    secp256k1_scalar s;
    secp256k1_scalar sigr;
    int overflow;
    unsigned char buf32[32];
    int high;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(adaptor_secret32 != NULL);
    ARG_CHECK(adaptor_sig192 != NULL);

    secp256k1_scalar_set_b32(&adaptor_secret, adaptor_secret32, &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_ecdsa_adaptor_sig_deserialize(NULL, &sigr, NULL, &sp, NULL, NULL, adaptor_sig192)) {
        secp256k1_scalar_clear(&adaptor_secret);
        return 0;
    }
    secp256k1_scalar_inverse(&s, &adaptor_secret);
    secp256k1_scalar_mul(&s, &s, &sp);
    high = secp256k1_scalar_is_high(&s);
    secp256k1_scalar_cond_negate(&s, high);

    secp256k1_ecdsa_signature_save(sig, &sigr, &s);

    memset(buf32, 0, sizeof(buf32));
    secp256k1_scalar_clear(&adaptor_secret);
    secp256k1_scalar_clear(&sp);
    secp256k1_scalar_clear(&s);

    return 1;
}

int secp256k1_ecdsa_adaptor_extract_secret(const secp256k1_context* ctx, unsigned char *adaptor_secret32, const secp256k1_ecdsa_signature *sig, const unsigned char *adaptor_sig162, const secp256k1_pubkey *adaptor) {
    secp256k1_scalar sp, adaptor_sigr;
    secp256k1_scalar s, r;
    secp256k1_scalar adaptor_secret;
    secp256k1_ge adaptor_expected_ge;
    secp256k1_gej adaptor_expected_gej;
    secp256k1_pubkey adaptor_expected;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(adaptor_secret32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(adaptor_sig162 != NULL);
    ARG_CHECK(adaptor != NULL);

    if (!secp256k1_ecdsa_adaptor_sig_deserialize(NULL, &adaptor_sigr, NULL, &sp, NULL, NULL, adaptor_sig162)) {
        return 0;
    }
    secp256k1_ecdsa_signature_load(ctx, &r, &s, sig);
    /* Check that we're not looking at some unrelated signature */
    if (!secp256k1_scalar_eq(&adaptor_sigr, &r)) {
        return 0;
    }
    secp256k1_scalar_inverse(&adaptor_secret, &s);
    secp256k1_scalar_mul(&adaptor_secret, &adaptor_secret, &sp);

    /* Deal with ECDSA malleability */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &adaptor_expected_gej, &adaptor_secret);
    secp256k1_ge_set_gej(&adaptor_expected_ge, &adaptor_expected_gej);
    secp256k1_pubkey_save(&adaptor_expected, &adaptor_expected_ge);
    if (memcmp(&adaptor_expected, adaptor, sizeof(adaptor_expected)) != 0) {
        secp256k1_scalar_negate(&adaptor_secret, &adaptor_secret);
    }
    secp256k1_scalar_get_b32(adaptor_secret32, &adaptor_secret);

    secp256k1_scalar_clear(&adaptor_secret);
    secp256k1_scalar_clear(&sp);
    secp256k1_scalar_clear(&s);

    return 1;
}

#endif /* SECP256K1_MODULE_ECDSA_ADAPTOR_MAIN_H */
