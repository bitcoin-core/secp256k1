#ifndef SECP256K1_SCHNORRSIG_H
#define SECP256K1_SCHNORRSIG_H

#include <stdint.h>

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements a variant of Schnorr signatures compliant with
 *  Bitcoin Improvement Proposal 340 "Schnorr Signatures for secp256k1"
 *  (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
 */

/** Data structure that holds a sign-to-contract ("s2c") opening information.
 *  Sign-to-contract allows a signer to commit to some data as part of a signature. It
 *  can be used as an Out-argument in certain signing functions.
 *
 *  This structure is not opaque, but it is strongly discouraged to read or write to
 *  it directly.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It can
 *  be safely copied/moved.
 */
typedef struct {
    /* magic is set during initialization */
    uint64_t magic;
    /* Public nonce before applying the sign-to-contract commitment */
    secp256k1_pubkey original_pubnonce;
    /* Byte indicating if signing algorithm negated the nonce. Alternatively when
     * verifying we could compute the EC commitment of original_pubnonce and the
     * data and negate if this would not be a valid nonce. But this would prevent
     * batch verification of sign-to-contract commitments. */
    int nonce_is_negated;
} secp256k1_schnorrsig_s2c_opening;

/** The signer commitment in the anti-exfil protocol is the original public nonce. */
typedef secp256k1_pubkey secp256k1_schnorrsig_anti_exfil_signer_commitment;

/** Parse a sign-to-contract opening.
 *
 *  Returns: 1 if the opening was fully valid.
 *           0 if the opening could not be parsed or is invalid.
 *  Args:    ctx: a secp256k1 context object.
 *  Out: opening: pointer to an opening object. If 1 is returned, it is set to a
 *                 parsed version of input. If not, its value is undefined.
 *  In:  input33: pointer to 33-byte array with a serialized opening
 *
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_s2c_opening_parse(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig_s2c_opening* opening,
    const unsigned char *input33
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize a sign-to-contract opening into a byte sequence.
 *
 *  Returns: 1 if the opening was successfully serialized.
 *           0 if the opening was not initializaed.
 *  Args:     ctx: a secp256k1 context object.
 *  Out: output33: pointer to a 33-byte array to place the serialized opening
 *                 in.
 *  In:   opening: a pointer to an initialized `secp256k1_schnorrsig_s2c_opening`.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_s2c_opening_serialize(
    const secp256k1_context* ctx,
    unsigned char *output33,
    const secp256k1_schnorrsig_s2c_opening* opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** A pointer to a function to deterministically generate a nonce.
 *
 *  Same as secp256k1_nonce function with the exception of accepting an
 *  additional pubkey argument and not requiring an attempt argument. The pubkey
 *  argument can protect signature schemes with key-prefixed challenge hash
 *  inputs against reusing the nonce when signing with the wrong precomputed
 *  pubkey.
 *
 *  Returns: 1 if a nonce was successfully generated. 0 will cause signing to
 *           return an error.
 *  Out:  nonce32: pointer to a 32-byte array to be filled by the function
 *  In:       msg: the message being verified. Is NULL if and only if msglen
 *                 is 0.
 *         msglen: the length of the message
 *          key32: pointer to a 32-byte secret key (will not be NULL)
 *     xonly_pk32: the 32-byte serialized xonly pubkey corresponding to key32
 *                 (will not be NULL)
 *           algo: pointer to an array describing the signature
 *                 algorithm (will not be NULL)
 *        algolen: the length of the algo array
 *           data: arbitrary data pointer that is passed through
 *
 *  Except for test cases, this function should compute some cryptographic hash of
 *  the message, the key, the pubkey, the algorithm description, and data.
 */
typedef int (*secp256k1_nonce_function_hardened)(
    unsigned char *nonce32,
    const unsigned char *msg,
    size_t msglen,
    const unsigned char *key32,
    const unsigned char *xonly_pk32,
    const unsigned char *algo,
    size_t algolen,
    void *data
);

/** An implementation of the nonce generation function as defined in Bitcoin
 *  Improvement Proposal 340 "Schnorr Signatures for secp256k1"
 *  (https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).
 *
 *  If a data pointer is passed, it is assumed to be a pointer to 32 bytes of
 *  auxiliary random data as defined in BIP-340. If the data pointer is NULL,
 *  the nonce derivation procedure follows BIP-340 by setting the auxiliary
 *  random data to zero. The algo argument must be non-NULL, otherwise the
 *  function will fail and return 0. The hash will be tagged with algo.
 *  Therefore, to create BIP-340 compliant signatures, algo must be set to
 *  "BIP0340/nonce" and algolen to 13.
 */
SECP256K1_API const secp256k1_nonce_function_hardened secp256k1_nonce_function_bip340;

/** First version of the extraparams struct. See `secp256k1_schnorrsig_extraparams` for the
    latest version and its documentation.
 */
typedef struct {
    unsigned char magic[4];
    secp256k1_nonce_function_hardened noncefp;
    void *ndata;
} secp256k1_schnorrsig_extraparams_v0;

/** Data structure that contains additional arguments for schnorrsig_sign_custom.
 *
 *  A schnorrsig_extraparams structure object can be initialized correctly by
 *  setting it to SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT.
 *
 *  Members:
 *         magic: set to SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC at initialization
 *                and has no other function than making sure the object is
 *                initialized.
 *       noncefp: pointer to a nonce generation function. If NULL,
 *                secp256k1_nonce_function_bip340 is used
 *         ndata: pointer to arbitrary data used by the nonce generation function
 *                (can be NULL). If it is non-NULL and
 *                secp256k1_nonce_function_bip340 is used, then ndata must be a
 *                pointer to 32-byte auxiliary randomness as per BIP-340.
 *   s2c_opening: pointer to an secp256k1_schnorrsig_s2c_opening structure which can be
 *                NULL but is required to be not NULL if this signature creates
 *                a sign-to-contract commitment (i.e. the `s2c_data32` argument
 *                is not NULL).
 *    s2c_data32: pointer to a 32-byte data to create an optional
 *                sign-to-contract commitment to if not NULL (can be NULL).
 */
typedef struct secp256k1_schnorrsig_extraparams {
    unsigned char magic[4];
    secp256k1_nonce_function_hardened noncefp;
    void *ndata;
    secp256k1_schnorrsig_s2c_opening* s2c_opening;
    const unsigned char* s2c_data32;
} secp256k1_schnorrsig_extraparams_v1;

typedef secp256k1_schnorrsig_extraparams_v1 secp256k1_schnorrsig_extraparams;

#define SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC_V0 { 0xda, 0x6f, 0xb3, 0x8c }
#define SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC_V1 { 0x05, 0x96, 0x5b, 0x5c }
#define SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC_V1

#define SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT_V0 {\
    SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC_V0,\
    NULL,\
    NULL\
}

#define SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT_V1 {\
    SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC_V1,\
    NULL,\
    NULL,\
    NULL,\
    NULL\
}
#define SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT_V1

/** Create a Schnorr signature.
 *
 *  Does _not_ strictly follow BIP-340 because it does not verify the resulting
 *  signature. Instead, you can manually use secp256k1_schnorrsig_verify and
 *  abort if it fails.
 *
 *  This function only signs 32-byte messages. If you have messages of a
 *  different size (or the same size but without a context-specific tag
 *  prefix), it is recommended to create a 32-byte message hash with
 *  secp256k1_tagged_sha256 and then sign the hash. Tagged hashing allows
 *  providing an context-specific tag for domain separation. This prevents
 *  signatures from being valid in multiple contexts by accident.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:    ctx: pointer to a context object (not secp256k1_context_static).
 *  Out:   sig64: pointer to a 64-byte array to store the serialized signature.
 *  In:    msg32: the 32-byte message being signed.
 *       keypair: pointer to an initialized keypair.
 *    aux_rand32: 32 bytes of fresh randomness. While recommended to provide
 *                this, it is only supplemental to security and can be NULL. A
 *                NULL argument is treated the same as an all-zero one. See
 *                BIP-340 "Default Signing" for a full explanation of this
 *                argument and for guidance if randomness is expensive.
 */
SECP256K1_API int secp256k1_schnorrsig_sign32(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    const unsigned char *aux_rand32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Same as secp256k1_schnorrsig_sign32, but DEPRECATED. Will be removed in
 *  future versions. */
SECP256K1_API int secp256k1_schnorrsig_sign(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *msg32,
    const secp256k1_keypair *keypair,
    const unsigned char *aux_rand32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4)
  SECP256K1_DEPRECATED("Use secp256k1_schnorrsig_sign32 instead");

/** Create a Schnorr signature with a more flexible API.
 *
 *  Same arguments as secp256k1_schnorrsig_sign except that it allows signing
 *  variable length messages and accepts a pointer to an extraparams object that
 *  allows customizing signing by passing additional arguments.
 *
 *  Equivalent to secp256k1_schnorrsig_sign32(..., aux_rand32) if msglen is 32
 *  and extraparams is initialized as follows:
 *  ```
 *  secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
 *  extraparams.ndata = (unsigned char*)aux_rand32;
 *  ```
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:   ctx: pointer to a context object (not secp256k1_context_static).
 *  Out:  sig64: pointer to a 64-byte array to store the serialized signature.
 *  In:     msg: the message being signed. Can only be NULL if msglen is 0.
 *       msglen: length of the message.
 *      keypair: pointer to an initialized keypair.
 *  extraparams: pointer to an extraparams object (can be NULL).
 */
SECP256K1_API int secp256k1_schnorrsig_sign_custom(
    const secp256k1_context *ctx,
    unsigned char *sig64,
    const unsigned char *msg,
    size_t msglen,
    const secp256k1_keypair *keypair,
    secp256k1_schnorrsig_extraparams *extraparams
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5);

/** Verify a Schnorr signature.
 *
 *  Returns: 1: correct signature
 *           0: incorrect signature
 *  Args:    ctx: pointer to a context object.
 *  In:    sig64: pointer to the 64-byte signature to verify.
 *           msg: the message being verified. Can only be NULL if msglen is 0.
 *        msglen: length of the message
 *        pubkey: pointer to an x-only public key to verify with
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_verify(
    const secp256k1_context *ctx,
    const unsigned char *sig64,
    const unsigned char *msg,
    size_t msglen,
    const secp256k1_xonly_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5);

/** Schnorr Anti-Exfil Protocol
 *
 *  The secp256k1_schnorrsig_anti_exfil_*, functions can be used to prevent a signing device from
 *  exfiltrating the secret signing keys through biased signature nonces. The general
 *  idea is that a host provides additional randomness to the signing device client
 *  and the client commits to the randomness in the nonce using sign-to-contract.
 *
 *  The following scheme is described by Stepan Snigirev here:
 *    https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-February/017655.html
 *  and by Pieter Wuille (as "Scheme 6") here:
 *    https://lists.linuxfoundation.org/pipermail/bitcoin-dev/2020-March/017667.html
 *
 *  In order to ensure the host cannot trick the signing device into revealing its
 *  keys, or the signing device to bias the nonce despite the host's contributions,
 *  the host and client must engage in a commit-reveal protocol as follows:
 *  1. The host draws randomness `rho` and computes a sha256 commitment to it using
 *     `secp256k1_schnorrsig_anti_exfil_host_commit`. It sends this to the signing device.
 *  2. The signing device computes a public nonce `R` using the host's commitment
 *     as auxiliary randomness, using `secp256k1_schnorrsig_anti_exfil_signer_commit`.
 *     The signing device sends the resulting `R` to the host as a s2c_opening.
 *
 *     If, at any point from this step onward, the hardware device fails, it is
 *     okay to restart the protocol using **exactly the same `rho`** and checking
 *     that the hardware device proposes **exactly the same** `R`. Otherwise, the
 *     hardware device may be selectively aborting and thereby biasing the set of
 *     nonces that are used in actual signatures.
 *
 *     It takes many (>100) such aborts before there is a plausible attack, given
 *     current knowledge in 2024. However such aborts accumulate even across a total
 *     replacement of all relevant devices (but not across replacement of the actual
 *     signing keys with new independently random ones).
 *
 *     In case the hardware device cannot be made to sign with the given `rho`, `R`
 *     pair, wallet authors should alert the user and present a very scary message
 *     implying that if this happens more than even a few times, say 20 or more times
 *     EVER, they should change hardware vendors and perhaps sweep their coins.
 *
 *  3. The host replies with `rho` generated in step 1.
 *  4. The device signs with `secp256k1_schnorrsig_sign_custom`, using `rho` as `s2c_data32` of the
 *     extraparams, and sends the signature to the host.
 *  5. The host verifies that the signature's public nonce matches the opening from
 *     step 2 and its original randomness `rho`, using `secp256k1_schnorrsig_anti_exfil_host_verify`.
 *
 *  Rationale:
 *      - The reason for having a host commitment is to allow the signing device to
 *        deterministically derive a unique nonce even if the host restarts the protocol
 *        using the same message and keys. Otherwise the signer might reuse the original
 *        nonce in two iterations of the protocol with different `rho`, which leaks the
 *        the secret key.
 *      - The signer does not need to check that the host commitment matches the host's
 *        claimed `rho`. Instead it re-derives the commitment (and its original `R`) from
 *        the provided `rho`. If this differs from the original commitment, the result
 *        will be an invalid `s2c_opening`, but since `R` was unique there is no risk to
 *        the signer's secret keys. Because of this, the signing device does not need to
 *        maintain any state about the progress of the protocol.
 */

/** Verify a sign-to-contract commitment.
 *
 *  Returns: 1: the signature contains a commitment to data32
 *           0: incorrect opening
 *  Args:    ctx: a secp256k1 context object, initialized for verification.
 *  In:    sig64: the signature containing the sign-to-contract commitment (cannot be NULL)
 *        data32: the 32-byte data that was committed to (cannot be NULL)
 *       opening: pointer to the opening created during signing (cannot be NULL)
 */
SECP256K1_API int secp256k1_schnorrsig_verify_s2c_commit(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *data32,
    const secp256k1_schnorrsig_s2c_opening *opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);


/** Create the initial host commitment to `rho`. Part of the Anti-Exfil Protocol.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:              ctx: pointer to a context object (cannot be NULL)
 *  Out: rand_commitment32: pointer to 32-byte array to store the returned commitment (cannot be NULL)
 *  In:             rand32: the 32-byte randomness to commit to (cannot be NULL). It must come from
 *                          a cryptographically secure RNG. As per the protocol, this value must not
 *                          be revealed to the client until after the host has received the client
 *                          commitment.
 */
SECP256K1_API int secp256k1_schnorrsig_anti_exfil_host_commit(
    const secp256k1_context* ctx,
    unsigned char* rand_commitment32,
    const unsigned char* rand32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

 /** Compute signer's original nonce. Part of the Anti-Exfil Protocol.
 *
 *  Returns 1 on success, 0 on failure.
 *  Args:           ctx: pointer to a context object, initialized for signing (cannot be NULL)
 *  Out:    signer_commitment:  where the signer's public nonce will be placed. (cannot be NULL)
 *  In:                   msg: the message to be signed (cannot be NULL)
 *                     msglen: length of the message
 *                    keypair: pointer to an initialized keypair (cannot be NULL).
 *          rand_commitment32: the 32-byte randomness commitment from the host (cannot be NULL)
 */
SECP256K1_API int secp256k1_schnorrsig_anti_exfil_signer_commit(
    const secp256k1_context* ctx,
    secp256k1_schnorrsig_anti_exfil_signer_commitment* signer_commitment,
    const unsigned char *msg,
    size_t msglen,
    const secp256k1_keypair *keypair,
    const unsigned char* rand_commitment32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Verify a signature was correctly constructed using the Anti-Exfil Protocol.
 *
 *  Returns: 1: the signature is valid and contains a commitment to host_data32
 *           0: failure
 *  Args:          ctx: a secp256k1 context object, initialized for verification.
 *  In:          sig64: pointer to the 64-byte signature to verify.
 *                 msg: the message being verified. Can only be NULL if msglen is 0.
 *              msglen: length of the message
 *              pubkey: pointer to an x-only public key to verify with (cannot be NULL)
 *         host_data32: the 32-byte data provided by the host (cannot be NULL)
 *   signer_commitment: signer commitment produced by `secp256k1_schnorrsig_anti_exfil_signer_commit()`.
 *             opening: the s2c opening provided by the signer (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorrsig_anti_exfil_host_verify(
    const secp256k1_context* ctx,
    const unsigned char *sig64,
    const unsigned char *msg,
    size_t msglen,
    const secp256k1_xonly_pubkey *pubkey,
    const unsigned char *host_data32,
    const secp256k1_schnorrsig_anti_exfil_signer_commitment *signer_commitment,
    const secp256k1_schnorrsig_s2c_opening *opening
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7) SECP256K1_ARG_NONNULL(8);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SCHNORRSIG_H */
