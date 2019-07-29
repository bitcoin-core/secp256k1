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

/** Create a randomness commitment on the host as part of the ECDSA Anti Nonce Covert Channel Protocol.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:              ctx: pointer to a context object (cannot be NULL)
 *  Out: rand_commitment32: pointer to 32-byte array to store the returned commitment (cannot be NULL)
 *  In:             rand32: the 32-byte randomness to commit to (cannot be NULL). It must come from
 *                          a cryptographically secure RNG. As per the protocol, this value must not
 *                          be revealed to the client until after the host has received the client
 *                          commitment.
 */
SECP256K1_API int secp256k1_ecdsa_s2c_anti_nonce_covert_channel_host_commit(
    secp256k1_context *ctx,
    unsigned char *rand_commitment32,
    const unsigned char *rand32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Compute commitment on the client as part of the ECDSA Anti Nonce Covert Channel Protocol.
 *
 *  ECDSA Anti Nonce Covert Channel Protocol:
 *
 *  The anti_nonce_covert_channel_* functions can be used to prevent a signing device from
 *  exfiltrating the secret signing keys through biased signature nonces. The general idea is that a
 *  host provides additional randomness to the signing device client and the client commits to the
 *  randomness in the nonce using sign-to-contract.
 *  In order to make the randomness unpredictable, the host and client must engage in a commit-reveal
 *  protocol as follows:
 *  1. The host draws randomness `k2`, commits to it with sha256 and sends the commitment to the client.
 *  2. The client commits to its original nonce `k1` using the host commitment by calling
 *     `secp256k1_ecdsa_anti_covert_channel_client_commit`. The client sends the resulting commitment
 *    `R1` to the host.
 *  3. The host replies with `k2` generated in step 1.
 *  4. The client signs with `secp256k1_ecdsa_s2c_sign`, using the `k2` as `s2c_data` and
 *     sends the signature and opening to the host.
 *  5. The host verifies that `R_x = (R1 + H(R1, k2)*G)_x`, where R_x is the `r` part of the signature by using
 *     `secp256k1_ecdsa_s2c_anti_nonce_covert_channel_host_verify` with the client's
 *      commitment from step 2 and the signature and opening received in step 4. If verification does
 *      not succeed, the protocol failed and can be restarted.
 *
 *  Rationale:
 *      - The reason for having a host commitment is to allow the client to derive a unique nonce
 *        for every host randomness. Otherwise the client would reuse the original nonce and thereby
 *        leaking the secret key to the host.
 *      - The client does not need to check that the host commitment matches the host's randomness.
 *        That's because the client derives its nonce using the hosts randomness commitment. If the
 *        commitment doesn't match then the client will derive a different original nonce and the
 *        only result will be that the host is not able to verify the sign-to-contract commitment.
 *        Therefore, the client does not need to maintain state about the progress of the protocol.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: pointer to a context object (cannot be NULL)
 *  Out:  client_commit: pointer to a pubkey where the clients public nonce will be
 *                       placed. (cannot be NULL)
 *  In:           msg32: the 32-byte message hash to be signed (cannot be NULL)
 *             seckey32: the 32-byte secret key used for signing (cannot be NULL)
 *    rand_commitment32: the 32-byte randomness commitment from the host (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_s2c_anti_nonce_covert_channel_client_commit(
    const secp256k1_context* ctx,
    secp256k1_pubkey *client_commit,
    const unsigned char *msg32,
    const unsigned char *seckey32,
    unsigned char *rand_commitment32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify that a clients signature contains the hosts randomness as part of the Anti
 *  Nonce Covert Channel Protocol. Does not verify the signature itself.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  In:           sig: pointer to the signature whose randomness should be verified
 *                     (cannot be NULL)
 *             rand32: pointer to the 32-byte randomness from the host which should
 *                     be included by the signature (cannot be NULL)
 *            opening: pointer to the opening produced by the client when signing
 *                     with `rand32` as `s2c_data` (cannot be NULL)
 *      client_commit: pointer to the client's commitment created in
 *                     `secp256k1_ecdsa_s2c_anti_nonce_covert_channel_client_commit`
 *                     (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_s2c_anti_nonce_covert_channel_host_verify(
    secp256k1_context *ctx,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *rand32,
    const secp256k1_s2c_opening *opening,
    const secp256k1_pubkey *client_commit
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ECDSA_SIGN_TO_CONTRACT_H */
