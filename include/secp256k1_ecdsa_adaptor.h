#ifndef SECP256K1_ECDSA_ADAPTOR_H
#define SECP256K1_ECDSA_ADAPTOR_H

#ifdef __cplusplus
extern "C" {
#endif

/** This module implements single signer ECDSA adaptor signatures following
 *  "One-Time Verifiably Encrypted Signatures A.K.A. Adaptor Signatures" by
 *  Lloyd Fournier
 *  (https://lists.linuxfoundation.org/pipermail/lightning-dev/2019-November/002316.html
 *  and https://github.com/LLFourn/one-time-VES/blob/master/main.pdf).
 *
 *  Note that at this module is currently a work in progress. It's not secure
 *  nor stable. Let me repeat: IT IS EXTREMELY DANGEROUS AND RECKLESS TO USE
 *  THIS MODULE IN PRODUCTION. DON'T!
 *
 *  This module passes a rudimentary test suite. But there are some things left
 *  TODO:
 *    - add API tests
 *    - add tests for the various overflow conditions
 *    - refactor adaptor verify to reuse code from secp256k1_ecdsa_verify()
 *    - test ecdsa_adaptor_sig_verify() more systematically. This is the most
 *      crucial function in this module. If it passes, we need to be sure that
 *      it is possible to compute the adaptor secret from the final ecdsa
 *      signature.
 *    - add ecdsa_adaptor_sign(), ecdsa_adaptor_adapt() and
 *      ecdsa_adaptor_extract_secret() to valgrind_ctime_test.c
 *    - allow using your own nonce function (noncefp, noncedata, synthetic
 *      nonces)
 *    - test module in travis
 *    - add comments to ease review
 */

/** Adaptor sign ("EncSign")
 *
 *  Creates an adaptor signature along with a proof to verify the adaptor
 *  signature.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:            ctx: a secp256k1 context object, initialized for signing
 *                        (cannot be NULL)
 *  Out:   adaptor_sig65: pointer to 65 byte to store the returned signature
 *                        (cannot be NULL)
 *       adaptor_proof97: pointer to 97 byte to store the adaptor proof (cannot be
 *                        NULL)
 *  In:         seckey32: pointer to 32 byte secret key corresponding to the
 *                        pubkey (cannot be NULL)
 *               adaptor: pointer to the adaptor point (cannot be NULL)
 *                 msg32: pointer to the 32-byte message to sign (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_adaptor_sign(
    const secp256k1_context* ctx,
    unsigned char *adaptor_sig65,
    unsigned char *adaptor_proof97,
    unsigned char *seckey32,
    const secp256k1_pubkey *adaptor,
    const unsigned char *msg32
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Adaptor verify ("EncVrfy")
 *
 *  Verifies that the adaptor secret can be extracted from the adaptor signature
 *  and the completed ECDSA signature.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:           ctx: a secp256k1 context object, initialized for verification
 *                       (cannot be NULL)
 *  In:   adaptor_sig65: pointer to 65-byte signature to verify (cannot be NULL)
 *               pubkey: pointer to the public key (cannot be NULL)
 *                msg32: pointer to the 32-byte message (cannot be NULL)
 *              adaptor: pointer to the adaptor point (cannot be NULL)
 *      adaptor_proof97: pointer to 97-byte adaptor proof (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_adaptor_sig_verify(
    const secp256k1_context* ctx,
    const unsigned char *adaptor_sig65,
    const secp256k1_pubkey *pubkey,
    const unsigned char *msg32,
    const secp256k1_pubkey *adaptor,
    const unsigned char *adaptor_proof97
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5) SECP256K1_ARG_NONNULL(6);

/** Adapt signature ("DecSig")
 *
 *  Creates an ECDSA signature from an adaptor signature and an adaptor secret.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:             ctx: a secp256k1 context object (cannot be NULL)
 *  Out:              sig: pointer to the ecdsa signature to create (cannot
 *                         be NULL)
 *  In:  adaptor_secret32: pointer to 32-byte byte adaptor secret of the adaptor
 *                         point (cannot be NULL)
 *          adaptor_sig65: pointer to 65-byte byte adaptor sig (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_adaptor_adapt(
    const secp256k1_context* ctx,
    secp256k1_ecdsa_signature *sig,
    const unsigned char *adaptor_secret32,
    const unsigned char *adaptor_sig65
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Adaptor extract ("Rec")
 *
 *  Extracts the adaptor secret from the complete signature and the adaptor
 *  signature.
 *
 *  Returns: 1 on success, 0 on failure
 *  Args:             ctx: a secp256k1 context object, initialized for signing
 *                         (cannot be NULL)
 *  Out: adaptor_secret32: pointer to 32-byte adaptor secret of the adaptor point
 *                         (cannot be NULL)
 *  In:               sig: pointer to ecdsa signature to extract the adaptor_secret
 *                         from (cannot be NULL)
 *            adaptor_sig: pointer to adaptor sig to extract the adaptor_secret
 *                         from (cannot be NULL)
 *                adaptor: pointer to the adaptor point (cannot be NULL)
 */
SECP256K1_API int secp256k1_ecdsa_adaptor_extract_secret(
    const secp256k1_context* ctx,
    unsigned char *adaptor_secret32,
    const secp256k1_ecdsa_signature *sig,
    const unsigned char *adaptor_sig65,
    const secp256k1_pubkey *adaptor
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4) SECP256K1_ARG_NONNULL(5);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_ADAPTOR_H */
