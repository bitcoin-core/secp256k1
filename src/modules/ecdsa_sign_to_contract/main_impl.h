/**********************************************************************
 * Copyright (c) 2019 Marko Bencun, Jonas Nick                        *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_SIGN_TO_CONTRACT_MAIN_H
#define SECP256K1_MODULE_ECDSA_SIGN_TO_CONTRACT_MAIN_H

#include "include/secp256k1_ecdsa_sign_to_contract.h"

int secp256k1_ecdsa_s2c_sign(const secp256k1_context *ctx, secp256k1_ecdsa_signature *signature, secp256k1_s2c_opening *s2c_opening, const unsigned char *msg32, const unsigned char *seckey, const unsigned char* s2c_data32, secp256k1_nonce_function noncefp, const void* noncedata) {
    secp256k1_scalar r, s;
    secp256k1_scalar sec, non, msg;
    secp256k1_sha256 sha;
    int ret = 0;
    int overflow = 0;
    int is_zero = 0;
    unsigned char ndata[32];
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(signature != NULL);
    ARG_CHECK(seckey != NULL);
    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_default;
    }
    /* sign-to-contract commitments only work with the default nonce function,
     * because we need to ensure that s2c_data is actually hashed into the nonce and
     * not just ignored. */
    ARG_CHECK(s2c_data32 == NULL || noncefp == secp256k1_nonce_function_default);
    /* s2c_opening and s2c_data32 should be either both non-NULL or both NULL. */
    ARG_CHECK((s2c_opening != NULL) == (s2c_data32 != NULL));

    if (s2c_opening != NULL) {
        secp256k1_s2c_opening_init(s2c_opening);
    }

    if(s2c_data32 != NULL) {
        /* Provide s2c_data32 and ndata (if not NULL) to the the nonce function
         * as additional data to derive the nonce from. If both pointers are
         * not NULL, they need to be hashed to get the nonce data 32 bytes.
         * Even if only s2c_data32 is not NULL, it's hashed because it should
         * be possible to derive nonces even if only a SHA256 commitment to the
         * data is known.  This is for example important in the
         * anti-nonce-sidechannel protocol.
         */
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, s2c_data32, 32);
        if (noncedata != NULL) {
            secp256k1_sha256_write(&sha, noncedata, 32);
        }
        secp256k1_sha256_finalize(&sha, ndata);
        noncedata = &ndata;
    }

    secp256k1_scalar_set_b32(&sec, seckey, &overflow);
    /* Fail if the secret key is invalid. */
    if (!overflow && !secp256k1_scalar_is_zero(&sec)) {
        unsigned char nonce32[32];
        unsigned int count = 0;
        secp256k1_scalar_set_b32(&msg, msg32, NULL);
        while (1) {
            ret = noncefp(nonce32, msg32, seckey, NULL, (void*)noncedata, count);
            if (!ret) {
                break;
            }
            secp256k1_scalar_set_b32(&non, nonce32, &overflow);
            is_zero = secp256k1_scalar_is_zero(&non);
            if (!overflow && !is_zero) {
                if (s2c_data32 != NULL) {
                    secp256k1_gej nonce_pj;
                    secp256k1_ge nonce_p;

                    /* Compute original nonce commitment/pubkey */
                    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &nonce_pj, &non);
                    secp256k1_ge_set_gej(&nonce_p, &nonce_pj);
                    secp256k1_pubkey_save(&s2c_opening->original_pubnonce, &nonce_p);

                    /* Tweak nonce with s2c commitment. */
                    if (!secp256k1_ec_commit_seckey(ctx, nonce32, &s2c_opening->original_pubnonce, s2c_data32, 32)) {
                        return 0;
                    }
                    secp256k1_scalar_set_b32(&non, nonce32, &overflow);
                    is_zero = secp256k1_scalar_is_zero(&non);
                }

                if (!overflow && !is_zero) {
                    if (secp256k1_ecdsa_sig_sign(&ctx->ecmult_gen_ctx, &r, &s, &sec, &msg, &non, NULL)) {
                        break;
                    }
                }
            }
            count++;
        }
        memset(nonce32, 0, 32);
        secp256k1_scalar_clear(&msg);
        secp256k1_scalar_clear(&non);
        secp256k1_scalar_clear(&sec);
    }
    if (ret) {
        secp256k1_ecdsa_signature_save(signature, &r, &s);
    } else {
        memset(signature, 0, sizeof(*signature));
    }
    return ret;
}

int secp256k1_ecdsa_s2c_verify_commit(const secp256k1_context* ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *data32, const secp256k1_s2c_opening *opening) {
    secp256k1_pubkey commitment;
    secp256k1_ge commitment_ge;
    unsigned char x_bytes1[32];
    unsigned char x_bytes2[32];
    secp256k1_scalar sigr, sigs;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(data32 != NULL);
    ARG_CHECK(opening != NULL);
    ARG_CHECK(secp256k1_s2c_commit_is_init(opening));

    if (!secp256k1_ec_commit(ctx, &commitment, &opening->original_pubnonce, data32, 32)) {
        return 0;
    }

    /* Check that sigr (x coordinate of R) matches the x coordinate of the commitment. */
    secp256k1_ecdsa_signature_load(ctx, &sigr, &sigs, sig);

    if (!secp256k1_pubkey_load(ctx, &commitment_ge, &commitment)) {
        return 0;
    }
    secp256k1_fe_normalize(&commitment_ge.x);
    secp256k1_fe_get_b32(x_bytes1, &commitment_ge.x);
    secp256k1_scalar_get_b32(x_bytes2, &sigr);
    return memcmp(x_bytes1, x_bytes2, 32) == 0;

}

int secp256k1_ecdsa_s2c_anti_nonce_covert_channel_client_commit(const secp256k1_context* ctx, secp256k1_pubkey *client_commit, const unsigned char *msg32, const unsigned char *seckey32, unsigned char *rand_commitment32) {
    unsigned char nonce32[32];
    secp256k1_scalar k;
    secp256k1_gej rj;
    secp256k1_ge r;
    unsigned int count = 0;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(client_commit != NULL);
    ARG_CHECK(msg32 != NULL);
    ARG_CHECK(seckey32 != NULL);
    ARG_CHECK(rand_commitment32 != NULL);

    while (1) {
        int overflow = 0;
        if (!secp256k1_nonce_function_default(nonce32, msg32, seckey32, NULL, rand_commitment32, count)) {
            /* cannot happen with secp256k1_nonce_function_default */
            return 0;
        }

        secp256k1_scalar_set_b32(&k, nonce32, &overflow);
        if (!overflow && !secp256k1_scalar_is_zero(&k)) {
            break;
        }
        count++;
    }

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej(&r, &rj);
    secp256k1_pubkey_save(client_commit, &r);
    return 1;
}

int secp256k1_ecdsa_s2c_anti_nonce_covert_channel_host_verify(secp256k1_context *ctx, const secp256k1_ecdsa_signature *sig, const unsigned char *rand32, const secp256k1_s2c_opening *opening, const secp256k1_pubkey *client_commit) {

    secp256k1_ge gcommit;
    secp256k1_ge gopening;
    secp256k1_gej pj;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(rand32 != NULL);
    ARG_CHECK(opening != NULL);
    ARG_CHECK(secp256k1_s2c_commit_is_init(opening));
    ARG_CHECK(client_commit != NULL);

    /* Check that client_commit == opening->original_pubnonce */
    secp256k1_gej_set_infinity(&pj);
    if (!secp256k1_pubkey_load(ctx, &gcommit, client_commit)) {
        return 0;
    }
    secp256k1_ge_neg(&gcommit, &gcommit);
    secp256k1_gej_add_ge(&pj, &pj, &gcommit);
    if (!secp256k1_pubkey_load(ctx, &gopening, &opening->original_pubnonce)) {
        return 0;
    }
    secp256k1_gej_add_ge(&pj, &pj, &gopening);
    if (!secp256k1_gej_is_infinity(&pj)) {
        return 0;
    }
    if (!secp256k1_ecdsa_s2c_verify_commit(ctx, sig, rand32, opening)) {
        return 0;
    }
    return 1;
}

int secp256k1_ecdsa_s2c_anti_nonce_covert_channel_host_commit(secp256k1_context *ctx, unsigned char *rand_commitment32, const unsigned char *rand32) {
    secp256k1_sha256 sha;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rand_commitment32 != NULL);
    ARG_CHECK(rand32 != NULL);

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, rand32, 32);
    secp256k1_sha256_finalize(&sha, rand_commitment32);
    return 1;
}

#endif /* SECP256K1_ECDSA_SIGN_TO_CONTRACT_MAIN_H */
