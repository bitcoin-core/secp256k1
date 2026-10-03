#ifndef SECP256K1_DLEQ_H
#define SECP256K1_DLEQ_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module provides an implementation of Discrete Log Equality (DLEQ) proofs,
 *  as specified in BIP-374. A DLEQ proof allows proving knowledge of a discrete
 *  logarithm relationship between two pairs of elliptic curve points without
 *  revealing the secret scalar.
 *
 *  Specifically, given points A, B, C, and the generator G, a DLEQ proof
 *  demonstrates that A = a*G and C = a*B for the same scalar a, without
 *  revealing a.
 *
 *  The proof consists of two 32-byte scalars (e, s) totaling 64 bytes.
 *
 *  A proof can optionally be bound to a 32-byte message. The verifier must pass
 *  the same message as the prover (NULL if the prover passed NULL), otherwise
 *  verification fails.
 */

/** Generate a DLEQ proof.
 *
 *  Proves knowledge of scalar a such that A = a*G and C = a*B without
 *  revealing a.
 *
 *  Proofs are deterministic: the same secret key, base point, auxiliary
 *  randomness and message always produce the same proof.
 *
 *  Does _not_ strictly follow BIP-374 because it does not verify the resulting
 *  proof. Instead, you can manually use secp256k1_dleq_verify and abort if it
 *  fails.
 *
 *  Returns: 1 if proof generation succeeded
 *           0 if nonce generation failed (negligible probability) or
 *             if any input is invalid
 *
 *  Args:        ctx: pointer to a context object (not secp256k1_context_static)
 *  Out:     proof64: pointer to 64-byte proof = bytes(32, e) || bytes(32, s)
 *  In:     seckey32: pointer to 32-byte secret key (scalar a)
 *          pubkey_B: pointer to public key B (base point)
 *        aux_rand32: pointer to 32-byte auxiliary randomness (can be NULL)
 *                    BIP-374 recommends fresh randomness for each proof
 *             msg32: pointer to optional 32-byte message (can be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_dleq_prove(
    const secp256k1_context *ctx,
    unsigned char *proof64,
    const unsigned char *seckey32,
    const secp256k1_pubkey *pubkey_B,
    const unsigned char *aux_rand32,
    const unsigned char *msg32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Verify a DLEQ proof.
 *
 *  Verifies that A and C were generated from the same scalar.
 *
 *  Returns: 1 if proof is valid
 *           0 if proof is invalid or any input is invalid
 *
 *  Args:       ctx: pointer to a context object
 *  In:     proof64: pointer to 64-byte proof = bytes(32, e) || bytes(32, s)
 *         pubkey_A: pointer to public key A
 *         pubkey_B: pointer to public key B (base point)
 *         pubkey_C: pointer to public key C
 *            msg32: pointer to optional 32-byte message (can be NULL)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_dleq_verify(
    const secp256k1_context *ctx,
    const unsigned char *proof64,
    const secp256k1_pubkey *pubkey_A,
    const secp256k1_pubkey *pubkey_B,
    const secp256k1_pubkey *pubkey_C,
    const unsigned char *msg32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_DLEQ_H */
