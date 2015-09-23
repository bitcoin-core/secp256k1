#ifndef _SECP256K1_SCHNORR_
# define _SECP256K1_SCHNORR_

# include "secp256k1.h"

# ifdef __cplusplus
extern "C" {
# endif

/** Create a signature using a custom EC-Schnorr-SHA256 construction. It
 *  produces non-malleable 64-byte signatures which support public key recovery
 *  batch validation, and multiparty signing.
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
int secp256k1_schnorr_sign(
  const secp256k1_context* ctx,
  unsigned char *sig64,
  const unsigned char *msg32,
  const unsigned char *seckey,
  secp256k1_nonce_function noncefp,
  const void *ndata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Verify a signature created by secp256k1_schnorr_sign.
 *  Returns: 1: correct signature
 *           0: incorrect signature
 *  Args:    ctx:       a secp256k1 context object, initialized for verification.
 *  In:      sig64:     the 64-byte signature being verified (cannot be NULL)
 *           msg32:     the 32-byte message hash being verified (cannot be NULL)
 *           pubkey:    the public key to verify with (cannot be NULL)
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorr_verify(
  const secp256k1_context* ctx,
  const unsigned char *sig64,
  const unsigned char *msg32,
  const secp256k1_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Recover an EC public key from a Schnorr signature created using
 *  secp256k1_schnorr_sign.
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
 */
int secp256k1_schnorr_recover(
  const secp256k1_context* ctx,
  secp256k1_pubkey *pubkey,
  const unsigned char *sig64,
  const unsigned char *msg32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Produce a 96-byte first stage partial multisignature.
 *  Returns: 1: a first stage partial signature was created
 *           0: otherwise (nonce generation failed, invalid private key, or
 *              a very unlikely unsignable combination)
 *  Args:    ctx:       pointer to a context object, initialized for signing
 *                      (cannot be NULL)
 *  Out:     stage1sig96: pointer to a 96-byte array to store the signature
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL,
 *                   secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation
 *                   function (can be NULL)
 *
 *  Internal details:
 *    The 96-byte structure consists of:
 *    - 32-byte serialization of the r that would be used in a normal signature
 *      of msg32 using key sec32
 *    - a 64-byte normal signature of SHA256(R || msg32) using key sec32
 *    Its purpose is simply communicating the nonce that was committed to for
 *    signing, and proving access to the corresponding private key.
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorr_multisign_stage1(
  const secp256k1_context* ctx,
  unsigned char *stage1sig96,
  const unsigned char *msg32,
  const unsigned char *sec32,
  secp256k1_nonce_function noncefp,
  const void* noncedata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Produce a 64-byte second partial multisignature, given all first stages.
 *  Returns: 1: a second stage partial signature was created.
 *           0: otherwise (nonce generation failed, invalid private key,
 *              invalid stage1 signatures, or a very unlikely unsignable
 *              combination)
 *  Args:    ctx:       pointer to a context object, initialized for signing
 *                      and verification (cannot be NULL)
 *  Out:     stage2sig64: pointer to a 64-byte array to store the signature
 *  In:      msg32:  the 32-byte message hash being signed (cannot be NULL)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL)
 *           noncefp:pointer to a nonce generation function. If NULL,
 *                   secp256k1_nonce_function_default is used
 *           ndata:  pointer to arbitrary data used by the nonce generation
 *                   function (can be NULL)
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorr_multisign_stage2(
  const secp256k1_context* ctx,
  unsigned char *stage2sig64,
  const unsigned char * const * other_stage1sig96s,
  size_t num_others,
  const unsigned char *msg32,
  const secp256k1_pubkey * const *other_pubkeys,
  const unsigned char *sec32,
  secp256k1_nonce_function noncefp,
  const void* noncedata
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(6) SECP256K1_ARG_NONNULL(7);

/** Combine multiple Schnorr partial signatures.
 * Returns: 1: the passed signatures were succesfully combined.
 *          0: the resulting signature is not valid (chance of 1 in 2^256) or the inputs were not created using the same set of keys
 * Args:   ctx:      pointer to a context object
 * Out:    sig64:    pointer to a 64-byte array to place the combined signature
 *                   (cannot be NULL)
 * In:     sig64sin: pointer to an array of n pointers to 64-byte input
 *                   signatures
 *         n:        the number of signatures to combine (at least 1)
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_schnorr_multisign_combine(
  const secp256k1_context* ctx,
  unsigned char *sig64,
  const unsigned char * const * stage2sig64s,
  int n
) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

# ifdef __cplusplus
}
# endif

#endif
