#ifndef _SECP256K1_
# define _SECP256K1_

# ifdef __cplusplus
extern "C" {
# endif

# if !defined(SECP256K1_GNUC_PREREQ)
#  if defined(__GNUC__)&&defined(__GNUC_MINOR__)
#   define SECP256K1_GNUC_PREREQ(_maj,_min) \
 ((__GNUC__<<16)+__GNUC_MINOR__>=((_maj)<<16)+(_min))
#  else
#   define SECP256K1_GNUC_PREREQ(_maj,_min) 0
#  endif
# endif

# if (!defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L) )
#  if SECP256K1_GNUC_PREREQ(2,7)
#   define SECP256K1_INLINE __inline__
#  elif (defined(_MSC_VER))
#   define SECP256K1_INLINE __inline
#  else
#   define SECP256K1_INLINE
#  endif
# else
#  define SECP256K1_INLINE inline
# endif

/**Warning attributes
  * NONNULL is not used if SECP256K1_BUILD is set to avoid the compiler optimizing out
  * some paranoid null checks. */
# if defined(__GNUC__) && SECP256K1_GNUC_PREREQ(3, 4)
#  define SECP256K1_WARN_UNUSED_RESULT __attribute__ ((__warn_unused_result__))
# else
#  define SECP256K1_WARN_UNUSED_RESULT
# endif
# if !defined(SECP256K1_BUILD) && defined(__GNUC__) && SECP256K1_GNUC_PREREQ(3, 4)
#  define SECP256K1_ARG_NONNULL(_x)  __attribute__ ((__nonnull__(_x)))
# else
#  define SECP256K1_ARG_NONNULL(_x)
# endif


/** Flags to pass to secp256k1_start. */
# define SECP256K1_START_VERIFY (1 << 0)
# define SECP256K1_START_SIGN   (1 << 1)

/** Initialize the library. This may take some time (10-100 ms).
 *  You need to call this before calling any other function.
 *  It cannot run in parallel with any other functions, but once
 *  secp256k1_start() returns, all other functions are thread-safe.
 */
void secp256k1_start(unsigned int flags);

/** Free all memory associated with this library. After this, no
 *  functions can be called anymore, except secp256k1_start()
 */
void secp256k1_stop(void);

/** Verify an ECDSA signature.
 *  Returns: 1: correct signature
 *           0: incorrect signature
 *          -1: invalid public key
 *          -2: invalid signature
 * In:       msg:       the message being verified (cannot be NULL)
 *           msglen:    the length of the message (at most 32)
 *           sig:       the signature being verified (cannot be NULL)
 *           siglen:    the length of the signature
 *           pubkey:    the public key to verify with (cannot be NULL)
 *           pubkeylen: the length of pubkey
 * Requires starting using SECP256K1_START_VERIFY.
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_verify(
  const unsigned char *msg,
  int msglen,
  const unsigned char *sig,
  int siglen,
  const unsigned char *pubkey,
  int pubkeylen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);

/** Create an ECDSA signature.
 *  Returns: 1: signature created
 *           0: nonce invalid, try another one
 *  In:      msg:    the message being signed (cannot be NULL)
 *           msglen: the length of the message being signed (at most 32)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL, assumed to be valid)
 *           nonce:  pointer to a 32-byte nonce (cannot be NULL, generated with a cryptographic PRNG)
 *  Out:     sig:    pointer to an array where the signature will be placed (cannot be NULL)
 *  In/Out:  siglen: pointer to an int with the length of sig, which will be updated
 *                   to contain the actual signature length (<=72).
 * Requires starting using SECP256K1_START_SIGN.
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_sign(
  const unsigned char *msg,
  int msglen,
  unsigned char *sig,
  int *siglen,
  const unsigned char *seckey,
  const unsigned char *nonce
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Create a compact ECDSA signature (64 byte + recovery id).
 *  Returns: 1: signature created
 *           0: nonce invalid, try another one
 *  In:      msg:    the message being signed (cannot be NULL)
 *           msglen: the length of the message being signed (at most 32)
 *           seckey: pointer to a 32-byte secret key (cannot be NULL, assumed to be valid)
 *           nonce:  pointer to a 32-byte nonce (cannot be NULL, generated with a cryptographic PRNG)
 *  Out:     sig:    pointer to a 64-byte array where the signature will be placed (cannot be NULL)
 *           recid:  pointer to an int, which will be updated to contain the recovery id (can be NULL)
 * Requires starting using SECP256K1_START_SIGN.
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_sign_compact(
  const unsigned char *msg,
  int msglen,
  unsigned char *sig64,
  const unsigned char *seckey,
  const unsigned char *nonce,
  int *recid
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Recover an ECDSA public key from a compact signature.
 *  Returns: 1: public key successfully recovered (which guarantees a correct signature).
 *           0: otherwise.
 *  In:      msg:        the message assumed to be signed (cannot be NULL)
 *           msglen:     the length of the message (at most 32)
 *           sig64:      signature as 64 byte array (cannot be NULL)
 *           compressed: whether to recover a compressed or uncompressed pubkey
 *           recid:      the recovery id (0-3, as returned by ecdsa_sign_compact)
 *  Out:     pubkey:     pointer to a 33 or 65 byte array to put the pubkey (cannot be NULL)
 *           pubkeylen:  pointer to an int that will contain the pubkey length (cannot be NULL)
 * Requires starting using SECP256K1_START_VERIFY.
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ecdsa_recover_compact(
  const unsigned char *msg,
  int msglen,
  const unsigned char *sig64,
  unsigned char *pubkey,
  int *pubkeylen,
  int compressed,
  int recid
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

/** Verify an ECDSA secret key.
 *  Returns: 1: secret key is valid
 *           0: secret key is invalid
 *  In:      seckey: pointer to a 32-byte secret key (cannot be NULL)
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_seckey_verify(const unsigned char *seckey) SECP256K1_ARG_NONNULL(1);

/** Just validate a public key.
 *  Returns: 1: valid public key
 *           0: invalid public key
 *  In:      pubkey:    pointer to a 33-byte or 65-byte public key (cannot be NULL).
 *           pubkeylen: length of pubkey
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_pubkey_verify(const unsigned char *pubkey, int pubkeylen) SECP256K1_ARG_NONNULL(1);

/** Compute the public key for a secret key.
 *  In:     compressed: whether the computed public key should be compressed
 *          seckey:     pointer to a 32-byte private key (cannot be NULL)
 *  Out:    pubkey:     pointer to a 33-byte (if compressed) or 65-byte (if uncompressed)
 *                      area to store the public key (cannot be NULL)
 *          pubkeylen:  pointer to int that will be updated to contains the pubkey's
 *                      length (cannot be NULL)
 *  Returns: 1: secret was valid, public key stores
 *           0: secret was invalid, try again.
 * Requires starting using SECP256K1_START_SIGN.
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_pubkey_create(
  unsigned char *pubkey,
  int *pubkeylen,
  const unsigned char *seckey,
  int compressed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Decompress a public key.
 * In/Out: pubkey:    pointer to a 65-byte array to put the decompressed public key.
                      It must contain a 33-byte or 65-byte public key already (cannot be NULL)
 *         pubkeylen: pointer to the size of the public key pointed to by pubkey (cannot be NULL)
                      It will be updated to reflect the new size.
 * Returns: 0 if the passed public key was invalid, 1 otherwise. If 1 is returned, the
            pubkey is replaced with its decompressed version.
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_pubkey_decompress(
  unsigned char *pubkey,
  int *pubkeylen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Export a private key in DER format. */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_privkey_export(
  const unsigned char *seckey,
  unsigned char *privkey,
  int *privkeylen,
  int compressed
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Import a private key in DER format. */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_privkey_import(
  unsigned char *seckey,
  const unsigned char *privkey,
  int privkeylen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Tweak a private key by adding tweak to it. */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_privkey_tweak_add(
  unsigned char *seckey,
  const unsigned char *tweak
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Tweak a public key by adding tweak times the generator to it.
 * Requires starting with SECP256K1_START_VERIFY.
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_pubkey_tweak_add(
  unsigned char *pubkey,
  int pubkeylen,
  const unsigned char *tweak
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3);

/** Tweak a private key by multiplying it with tweak. */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_privkey_tweak_mul(
  unsigned char *seckey,
  const unsigned char *tweak
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

/** Tweak a public key by multiplying it with tweak.
 * Requires starting with SECP256K1_START_VERIFY.
 */
SECP256K1_WARN_UNUSED_RESULT int secp256k1_ec_pubkey_tweak_mul(
  unsigned char *pubkey,
  int pubkeylen,
  const unsigned char *tweak
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(3);

/** Combine two public keys pubkey and pubkey2 (do an EC addition on the points), and put the result in pubkey. */
int secp256k1_ec_pubkey_combine(unsigned char *pubkey, int pubkeylen, const unsigned char *pubkey2, int pubkey2len);

/** A hash function for Schnorr
 *  In:  r32:    a pointer to a 32-byte value (the X coordinate of the public
 *               key corresponding to the nonce).
 *       msg:    a pointer to a the message to be signed.
 *       msglen: the length of the message being signed.
 *  Out: h32:    a pointer to a 32-byte value where the resulting hash is to be
 *               written. This is expected to be a hash of a concatenation of
 *               r32 and the message.
 */
typedef void (*secp256k1_schnorr_hash_t)(unsigned char *h32, const unsigned char *r32, const unsigned char *msg, int msglen);

/** Create a Schnorr signature.
 *  In:  msg:      a pointer to the message to be signed.
 *       msglen:   the length of the message to be signed.
 *       seckey32: a pointer to a 32-byte private key.
 *       nonce32:  a pointer to a 32-byte nonce.
 *       hash:     a hash function to use.
 *  Out: sig64:    a pointer to a 64-byte array where the Schnorr signature
 *                 will be put.
 */
int secp256k1_schnorr_sign(const unsigned char *msg, int msglen, unsigned char *sig64, const unsigned char *seckey32, const unsigned char *nonce32, secp256k1_schnorr_hash_t hash);

/** Verify a Schnorr signature.
 *  In:      msg:       a pointer to the message that was signed.
 *           msglen:    the length of the message that was signed.
 *           sig64:     a pointer to a 64-byte Schnorr signature.
 *           pubkey:    the public key corresponding to the private key that signed.
 *           pubkeylen: the length of the public key.
 *           hash:      the hash function to use.
 *  Returns: 1 if the public key is valid and the signature is valid for that
 *           message/public key combination. 0 otherwise.
 */
int secp256k1_schnorr_verify(const unsigned char *msg, int msglen, const unsigned char *sig64, const unsigned char *pubkey, int pubkeylen, secp256k1_schnorr_hash_t hash);

/** Create one part of a Schnorr multiparty signature.
 *  In:  msg:         a pointer to the message to be signed.
 *       msglen:      the length of the message to be signed.
 *       seckey32:    a pointer to a 32-byte private key.
 *       nonce32:     a pointer to a 32-byte nonce.
 *       allnonce:    a pointer to the public key which is the combination of all
 *                    nonces used in the multiparty signature. This can be
 *                    obtained by letting every participant publish the public key
 *                    corresponding to their nonce (through secp256k1_ec_pubkey_create),
 *                    and using secp256k1_ec_pubkey_combine to combine the results.
 *       allnoncelen: the length of the public key in allnonce.
 *       hash:        a hash function to use.
 *  Out: sig64:       a pointer to a 64-byte array where the Schnorr signature
 *                    will be put. After combining (using secp256k1_schnorr_combine),
 *                    the result will be verifiable by secp256k1_schnorr_verify,
 *                    using a public key that is the result of applying
 *                    secp256k1_ec_pubkey_combine on the individual public keys.
 */
int secp256k1_schnorr_multisign(const unsigned char *msg, int msglen, unsigned char *sig64, const unsigned char *seckey32, const unsigned char *nonce32, const unsigned char *allnonce, int allnoncelen, secp256k1_schnorr_hash_t hash);

/** Combine two Schnorr signatures (which must be for the same message, and the same set of nonces) into one. */
int secp256k1_schnorr_combine(unsigned char *sig64, const unsigned char *sig64a, const unsigned char *sig64b);

# ifdef __cplusplus
}
# endif

#endif
