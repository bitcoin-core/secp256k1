#ifndef SECP256K1_EXTRAKEYS_H
#define SECP256K1_EXTRAKEYS_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** Opaque data structure that holds a parsed and valid "x-only" public key.
 *  An x-only pubkey encodes a point whose Y coordinate is even. It is
 *  serialized using only its X coordinate (32 bytes). See BIP-340 for more
 *  information about x-only pubkeys.
 *
 *  The exact representation of data inside is implementation defined and not
 *  guaranteed to be portable between different platforms or versions. It is
 *  however guaranteed to be 64 bytes in size, and can be safely copied/moved.
 *  If you need to convert to a format suitable for storage, transmission, or
 *  comparison, use secp256k1_xonly_pubkey_serialize and
 *  secp256k1_xonly_pubkey_parse.
 */
typedef struct {
    unsigned char data[64];
} secp256k1_xonly_pubkey;

/** Parse a 32-byte sequence into a xonly_pubkey object.
 *
 *  Returns: 1 if the public key was fully valid.
 *           0 if the public key could not be parsed or is invalid.
 *
 *  Args:   ctx: a secp256k1 context object (cannot be NULL).
 *  Out: pubkey: pointer to a pubkey object. If 1 is returned, it is set to a
 *               parsed version of input. If not, it's set to an invalid value.
 *               (cannot be NULL).
 *  In: input32: pointer to a serialized xonly_pubkey (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_xonly_pubkey_parse(
    const secp256k1_context* ctx,
    secp256k1_xonly_pubkey* pubkey,
    const unsigned char *input32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Serialize an xonly_pubkey object into a 32-byte sequence.
 *
 *  Returns: 1 always.
 *
 *  Args:     ctx: a secp256k1 context object (cannot be NULL).
 *  Out: output32: a pointer to a 32-byte array to place the serialized key in
 *                 (cannot be NULL).
 *  In:    pubkey: a pointer to a secp256k1_xonly_pubkey containing an
 *                 initialized public key (cannot be NULL).
 */
SECP256K1_API int secp256k1_xonly_pubkey_serialize(
    const secp256k1_context* ctx,
    unsigned char *output32,
    const secp256k1_xonly_pubkey* pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Converts a secp256k1_pubkey into a secp256k1_xonly_pubkey.
 *
 *  Returns: 1 if the public key was successfully converted
 *           0 otherwise
 *
 *  Args:         ctx: pointer to a context object (cannot be NULL)
 *  Out: xonly_pubkey: pointer to an x-only public key object for placing the
 *                     converted public key (cannot be NULL)
 *          pk_parity: pointer to an integer that will be set to 1 if the point
 *                     encoded by xonly_pubkey is the negation of the pubkey and
 *                     set to 0 otherwise. (can be NULL)
 *  In:        pubkey: pointer to a public key that is converted (cannot be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_xonly_pubkey_from_pubkey(
    const secp256k1_context* ctx,
    secp256k1_xonly_pubkey *xonly_pubkey,
    int *pk_parity,
    const secp256k1_pubkey *pubkey
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_EXTRAKEYS_H */
