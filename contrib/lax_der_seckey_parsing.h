/**********************************************************************
 * Copyright (c) 2014, 2015 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

/****
 * Please do not link this file directly. It is not part of the libsecp256k1
 * project and does not promise any stability in its API, functionality or
 * presence. Projects which use this code should instead copy this header
 * and its accompanying .c file directly into their codebase.
 ****/

/* This file contains code snippets that parse DER secret keys with
 * various errors and violations.  This is not a part of the library
 * itself, because the allowed violations are chosen arbitrarily and
 * do not follow or establish any standard.
 *
 * It also contains code to serialize secret keys in a compatible
 * manner.
 *
 * These functions are meant for compatibility with applications
 * that require BER encoded keys. When working with secp256k1-specific
 * code, the simple 32-byte secret keys normally used by the
 * library are sufficient.
 */

#ifndef SECP256K1_CONTRIB_DER_SECKEY_H
#define SECP256K1_CONTRIB_DER_SECKEY_H

#include <secp256k1.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Export a secret key in DER format.
 *
 *  Returns: 1 if the secret key was valid.
 *  Args: ctx:          pointer to a context object, initialized for signing
 *                      (cannot be NULL).
 *  Out:  seckeyder:    pointer to an array for storing the secret key in DER
 *                      (should have space for 279 bytes, and cannot be NULL).
 *        seckeyderlen: pointer to a size_t in which the length of the exported
 *                      secret key will be stored (cannot be NULL).
 *  In:   seckey32:     pointer to a 32-byte secret key to export.
 *        compressed:   1 if the key should be exported in compressed format,
 *                      0 otherwise.
 *
 *  This function is purely meant for compatibility with applications that
 *  require DER encoded keys. When working with secp256k1-specific code, the
 *  simple 32-byte secret keys are sufficient.
 *
 *  Note that this function does not guarantee correct DER output. It is
 *  guaranteed to be parsable by secp256k1_ec_seckey_import_der.
 */
SECP256K1_WARN_UNUSED_RESULT int ec_seckey_export_der(
    const secp256k1_context* ctx,
    unsigned char *seckeyder,
    size_t *seckeyderlen,
    const unsigned char *seckey32,
    int compressed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Import a secret key in DER format.
 * Returns: 1 if a key was extracted.
 * Args: ctx:          pointer to a context object (cannot be NULL).
 * Out:  seckey32:     pointer to a 32-byte array for storing the secret key
 *                     (cannot be NULL).
 * In:   seckeyder:    pointer to a secret key in DER format (cannot be NULL).
 *       seckeyderlen: length of the DER secret key pointed to by seckeyder.
 *
 * This function will accept more than just strict DER, and even allow some BER
 * violations. The public key stored inside the DER-encoded secret key is not
 * verified for correctness, nor are the curve parameters. Use this function
 * only if you know in advance it is supposed to contain a secp256k1 secret key.
 */
SECP256K1_WARN_UNUSED_RESULT int ec_seckey_import_der(
    const secp256k1_context* ctx,
    unsigned char *seckey32,
    const unsigned char *seckeyder,
    size_t seckeyderlen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_CONTRIB_DER_SECKEY_H */
