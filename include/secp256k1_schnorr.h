#ifndef _SECP256K1_SCHNORR_
# define _SECP256K1_SCHNORR_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

/** This header file defines an API for a custom EC-Schnorr-SHA256 constructions.
 *  It supports non-malleable 64-byte signatures which support public key
 *  recovery, batch validation, and multiparty signing. See schnorr.md for more
 *  details.
 */

/** Create a single party Schnorr signature.
 *  Returns: 1: signature created
 *           0: the nonce generation function failed, or the private key was
 *              invalid.
 *  Args:    ctx:    pointer to a context object, initialized for signing
 *                   (cannot be NULL)
 *  Out:     sig64:  pointer to a 64-byte array where the signature will be
 *                   placed (cannot be NULL)
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL,
 *                   secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation
 *                   function (can be NULL)
 */
SECP256K1_API int secp256k1_schnorr_sign(
  const secp256k1_context* ctx,
  unsigned char *sig64,
  const unsigned char *msg32,
  const unsigned char *seckey,
  secp256k1_nonce_function noncefp,
  const void *ndata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Verify a Schnorr signature.
 *  Returns: 1: correct signature
 *           0: incorrect signature
 *  Args:    ctx:       a secp256k1 context object, initialized for verification.
 *  In:      sig64:     the 64-byte signature being verified (cannot be NULL)
 *           msg32:     the 32-byte message hash being verified (cannot be NULL)
 *           pubkey:    the public key to verify with (cannot be NULL)
 *
 *  Signatures verifiable by this function can be created using
 *  secp256k1_schnorr_sign, or secp256k1_multischnorr_combine_sigs.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorr_verify(
  const secp256k1_context* ctx,
  const unsigned char *sig64,
  const unsigned char *msg32,
  const secp256k1_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Recover an EC public key from a Schnorr signature.
 *  Returns: 1: public key successfully recovered (which guarantees a correct
 *           signature).
 *           0: otherwise.
 *  Args:    ctx:        pointer to a context object, initialized for
 *                       verification (cannot be NULL)
 *  Out:     pubkey:     pointer to a pubkey to set to the recovered public key
 *                       (cannot be NULL).
 *  In:      sig64:      signature as 64 byte array (cannot be NULL)
 *           msg32:      the 32-byte message hash assumed to be signed (cannot
 *                       be NULL)
 *
 *  Signatures recoverable by this function can be created using
 *  secp256k1_schnorr_sign, or secp256k1_multischnorr_combine_sigs.
 */
SECP256K1_API int secp256k1_schnorr_recover(
  const secp256k1_context* ctx,
  secp256k1_pubkey *pubkey,
  const unsigned char *sig64,
  const unsigned char *msg32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Produce a 32-byte first stage partial multisignature.
 *  Returns: 1: a first stage partial signature was created
 *           0: otherwise (nonce generation failed, invalid private key, or
 *              a very unlikely unsignable combination)
 *  Args:    ctx:       pointer to a context object, initialized for signing
 *                      (cannot be NULL)
 *  Out:     stage1sig32: pointer to a 32-byte array to store the signature
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL,
 *                   secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation
 *                   function (can be NULL)
 *
 *  All cosigners must use the same msg32, but may use different nonce
 *  generation parameters.
 *
 *  The purpose of the stage 1 round is establishing a shared public nonce that
 *  all cosigners agree on (without revealing their secret nonces), and proving
 *  access to their private keys.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_multischnorr_stage1(
  const secp256k1_context* ctx,
  unsigned char *stage1sig32,
  const unsigned char *msg32,
  const unsigned char *sec32,
  secp256k1_nonce_function noncefp,
  const void* noncedata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Produce a 64-byte second stage partial multisignature.
 *  Returns: 1: a second stage partial signature was created.
 *           0: otherwise (nonce generation failed, invalid private key,
 *              invalid stage 1 signatures, or a very unlikely unsignable
 *              combination)
 *  Args: ctx:               pointer to a context object, initialized for
 *                           signing and verification (cannot be NULL)
 *  Out: stage2sig64:        pointer to a 64-byte array to store the signature
 *  In:  other_stage1sig32s: pointer to an array of num_others pointers to
 *                           32-byte stage 1 partial multisignatures from all
 *                           other cosigners (can only be NULL if num_others is
 *                           0)
 *       num_others:         the number of cosigners (excluding yourself)
 *       msg32:              the 32-byte message hash being signed (cannot be
 *                           NULL)
 *       sec32:              pointer to a 32-byte secret key (cannot be NULL)
 *       noncefp:            pointer to a nonce generation function. If NULL,
 *                           secp256k1_nonce_function_default is used
 *       ndata:              pointer to arbitrary data used by the nonce
 *                           generation function (can be NULL)
 *
 *  The second stage uses the stage 1 partial signatures from all other
 *  cosigners and computes a stage 2 partial signature. If num_others is 0, the
 *  result is a full signature (though different than the one produced by
 *  secp256k1_schnorr_sign, given the same msg32, sec32, noncefp, ndata).
 *
 *  All cosigners must use the same msg32, and the same as in stage1. Different
 *  cosigners may use different nonce generating functions and data, as long as
 *  they are each consistent between stage 1 and stage 2.
 *
 *  The order of stage 1 signatures in other_stage1sig32s does not matter.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_multischnorr_stage2(
  const secp256k1_context* ctx,
  unsigned char *stage2sig64,
  const unsigned char * const * other_stage1sig96s,
  size_t num_others,
  const unsigned char *msg32,
  const unsigned char *sec32,
  secp256k1_nonce_function noncefp,
  const void* noncedata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Combine multiple Schnorr stage 2 partial signatures into a full signature.
 *  Returns: 1: the passed signatures were succesfully combined.
 *           0: the resulting signature is not valid (chance of 1 in 2^256) or
 *              the inputs were not created using the same set of keys
 *  Args:   ctx:          pointer to a context object
 *  Out:    sig64:        pointer to a 64-byte array to place the combined
 *                        full signature (cannot be NULL)
 *  In:     stage2sig64s: pointer to an array of n pointers to 64-byte stage 2
 *                        partial signatures (cannot be NULL)
 *          n:            the number of signatures to combine (at least 1)
 *
 *  The order of the stage 2 partial signatures in stage2sig64s does not matter.
 *
 *  If succesful, the resulting combined full signature will be verifiable with
 *  secp256k1_schnorr_verify(ctx, sig64, msg32, pub), where:
 *  - sig64 is the output of secp256k1_multischnorr_combine_sigs
 *  - msg32 is the message used by all cosigners in stage 1 and stage 2
 *  - pub is the result of secp256k1_multischnorr_combine_keys, applied to all
 *    cosigners' public keys (including yours).
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_multischnorr_combine_sigs(
  const secp256k1_context* ctx,
  unsigned char *sig64,
  const unsigned char * const * stage2sig64s,
  size_t n
) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Compute the combined public key that a multisignature will be verifiable
 *  with.
 *  Returns: 1: the sum of the public keys is valid.
 *           0: the sum of the public keys is not valid.
 *  Args:   ctx:        pointer to a context object
 *  Out:    out:        pointer to pubkey for placing the resulting public key
 *                      (cannot be NULL)
 *  In:     ins:        pointer to array of pointers to public keys (cannot be NULL)
 *          n:          the number of public keys to add together (must be at least 1)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_multischnorr_combine_keys(
    const secp256k1_context* ctx,
    secp256k1_pubkey *out,
    const secp256k1_pubkey * const * ins,
    size_t n
) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

# ifdef __cplusplus
}
# endif

#endif
