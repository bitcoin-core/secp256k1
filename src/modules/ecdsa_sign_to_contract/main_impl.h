/**********************************************************************
 * Copyright (c) 2019-2020 Marko Bencun, Jonas Nick                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_SIGN_TO_CONTRACT_MAIN_H
#define SECP256K1_MODULE_ECDSA_SIGN_TO_CONTRACT_MAIN_H

#include "include/secp256k1_ecdsa_sign_to_contract.h"

int secp256k1_ecdsa_s2c_sign(const secp256k1_context *ctx, secp256k1_ecdsa_signature *signature, secp256k1_s2c_opening *s2c_opening, const unsigned char *msg32, const unsigned char *seckey, const unsigned char* s2c_data32) {
    secp256k1_scalar r, s;
    int ret;
    unsigned char ndata[32];
    const unsigned char* noncedata = NULL;
    ARG_CHECK(signature != NULL);

    if(s2c_data32 != NULL) {
        /* Provide s2c_data32 to the the nonce function as additional data to derive the nonce
         * from. It's hashed because it should be possible to derive nonces even if only a SHA256
         * commitment to the data is known.  This is for example important in the
         * anti-nonce-covert-channel protocol.
         */
        secp256k1_sha256 sha;
        secp256k1_sha256_initialize(&sha);
        secp256k1_sha256_write(&sha, s2c_data32, 32);
        secp256k1_sha256_finalize(&sha, ndata);
        noncedata = ndata;
    }

    ret = secp256k1_ecdsa_sign_helper(ctx, &r, &s, s2c_opening, msg32, seckey, s2c_data32, NULL, noncedata, NULL);
    secp256k1_scalar_cmov(&r, &secp256k1_scalar_zero, !ret);
    secp256k1_scalar_cmov(&s, &secp256k1_scalar_zero, !ret);
    secp256k1_ecdsa_signature_save(signature, &r, &s);
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

    /* Check that sig_r == commitment_x (mod n)
     * sig_r is the x coordinate of R represented by a scalar.
     * commitment_x is the x coordinate of the commitment (field element).
     *
     * It is sufficient to only compare the x coordinates as it is as difficult to find an client
     * commitment to the negation of the point as to any other point. There is a small reduction in
     * security as it is easier to find a collision with a point and its negation.
     */
    secp256k1_ecdsa_signature_load(ctx, &sigr, &sigs, sig);

    if (!secp256k1_pubkey_load(ctx, &commitment_ge, &commitment)) {
        return 0;
    }
    secp256k1_fe_normalize(&commitment_ge.x);
    secp256k1_fe_get_b32(x_bytes1, &commitment_ge.x);
    secp256k1_scalar_get_b32(x_bytes2, &sigr);
    return memcmp(x_bytes1, x_bytes2, 32) == 0;

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
