/***********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                  *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ECDH_MAIN_H
#define SECP256K1_MODULE_ECDH_MAIN_H

#include "../../../include/secp256k1_ecdh.h"
#include "../../ecmult_const_impl.h"

static int ecdh_hash_function_sha256(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    unsigned char version = (y32[31] & 0x01) | 0x02;
    secp256k1_sha256 sha;
    (void)data;

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, &version, 1);
    secp256k1_sha256_write(&sha, x32, 32);
    secp256k1_sha256_finalize(&sha, output);

    return 1;
}

static int ecdh_xonly_hash_function_sha256(unsigned char *output, const unsigned char *x32, void *data) {
    secp256k1_sha256 sha;
    (void)data;

    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, x32, 32);
    secp256k1_sha256_finalize(&sha, output);

    return 1;
}

const secp256k1_ecdh_hash_function secp256k1_ecdh_hash_function_sha256 = ecdh_hash_function_sha256;
const secp256k1_ecdh_hash_function secp256k1_ecdh_hash_function_default = ecdh_hash_function_sha256;
const secp256k1_ecdh_xonly_hash_function secp256k1_ecdh_xonly_hash_function_sha256 = ecdh_xonly_hash_function_sha256;

int secp256k1_ecdh(const secp256k1_context* ctx, unsigned char *output, const secp256k1_pubkey *point, const unsigned char *scalar, secp256k1_ecdh_hash_function hashfp, void *data) {
    int ret = 0;
    int overflow = 0;
    secp256k1_gej res;
    secp256k1_ge pt;
    secp256k1_scalar s;
    unsigned char x[32];
    unsigned char y[32];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(point != NULL);
    ARG_CHECK(scalar != NULL);

    if (hashfp == NULL) {
        hashfp = secp256k1_ecdh_hash_function_default;
    }

    secp256k1_pubkey_load(ctx, &pt, point);
    secp256k1_scalar_set_b32(&s, scalar, &overflow);

    overflow |= secp256k1_scalar_is_zero(&s);
    secp256k1_scalar_cmov(&s, &secp256k1_scalar_one, overflow);

    secp256k1_ecmult_const(&res, &pt, &s);
    secp256k1_ge_set_gej(&pt, &res);

    /* Compute a hash of the point */
    secp256k1_fe_normalize(&pt.x);
    secp256k1_fe_normalize(&pt.y);
    secp256k1_fe_get_b32(x, &pt.x);
    secp256k1_fe_get_b32(y, &pt.y);

    ret = hashfp(output, x, y, data);

    memset(x, 0, 32);
    memset(y, 0, 32);
    secp256k1_scalar_clear(&s);

    return !!ret & !overflow;
}

int secp256k1_ecdh_xonly(const secp256k1_context* ctx, unsigned char *output, const unsigned char* xpubkey, const unsigned char *scalar, secp256k1_ecdh_xonly_hash_function hashfp, void *data) {
    int ret;
    int overflow;
    secp256k1_fe x;
    unsigned char x32[32];
    secp256k1_scalar s;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output != NULL);
    ARG_CHECK(xpubkey != NULL);
    ARG_CHECK(scalar != NULL);

    if (hashfp == NULL) {
        hashfp = secp256k1_ecdh_xonly_hash_function_sha256;
    }

    if (!secp256k1_fe_set_b32_limit(&x, xpubkey)) {
        /* X-only public key overflow, bail out early (we don't need to be constant time in pubkey). */
        memset(output, 0, 32);
        return 0;
    }

    secp256k1_scalar_set_b32(&s, scalar, &overflow);

    overflow |= secp256k1_scalar_is_zero(&s);
    secp256k1_scalar_cmov(&s, &secp256k1_scalar_one, overflow);

    if (!secp256k1_ecmult_const_xonly(&x, &x, NULL, &s, 0)) {
        /* Input is not a valid X coordinate, bail out early. */
        memset(output, 0, 32);
        return 0;
    }

    /* Compute a hash of the point */
    secp256k1_fe_normalize(&x);
    secp256k1_fe_get_b32(x32, &x);

    ret = hashfp(output, x32, data);

    memset(x32, 0, 32);
    secp256k1_scalar_clear(&s);

    return !!ret & !overflow;
}

#endif /* SECP256K1_MODULE_ECDH_MAIN_H */
