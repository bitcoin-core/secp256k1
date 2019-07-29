#ifndef SECP256K1_ECDSA_SIGN_TO_CONTRACT_H
#define SECP256K1_ECDSA_SIGN_TO_CONTRACT_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Same as secp256k1_ecdsa_sign, but s2c_data32 is committed to by adding `hash(k*G, s2c_data32)` to
 *  the signing nonce `k`.
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the private key was invalid.
 *  Args:    ctx:  pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:     sig:  pointer to an array where the signature will be placed (cannot be NULL)
 *   s2c_opening:  pointer to an secp256k1_s2c_opening structure which can be
 *                 NULL but is required to be not NULL if this signature creates
 *                 a sign-to-contract commitment (i.e. the `s2c_data` argument
 *                 is not NULL).
 *  In:
 *         msg32: the 32-byte message hash being signed (cannot be NULL)
 *        seckey: pointer to a 32-byte secret key (cannot be NULL)
 *    s2c_data32: pointer to a 32-byte data to create an optional
 *                sign-to-contract commitment to if not NULL (can be NULL).
 */
SECP256K1_API int secp256k1_ecdsa_s2c_sign(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sig,
    secp256k1_s2c_opening *s2c_opening,
    const unsigned char *msg32,
    const unsigned char *seckey,
    const unsigned char* s2c_data32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify a sign-to-contract commitment.
 *
 *  Returns: 1: the signature contains a commitment to data32
 *           0: incorrect opening
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:      sig: the signature containing the sign-to-contract commitment (cannot be NULL)
 *        data32: the 32-byte data that was committed to (cannot be NULL)
 *       opening: pointer to the opening created during signing (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_s2c_verify_commit(
    const secp256k1_context* ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *data32,
    const secp256k1_s2c_opening *opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECDSA_SIGN_TO_CONTRACT_H */
