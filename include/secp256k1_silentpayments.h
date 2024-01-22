#ifndef SECP256K1_SILENTPAYMENTS_H
#define SECP256K1_SILENTPAYMENTS_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/** This module provides an implementation for Silent Payments, as specified in
 *  BIP352. This particularly involves the creation of input tweak data by
 *  summing up secret or public keys and the derivation of a shared secret using
 *  Elliptic Curve Diffie-Hellman. Combined are either:
 *    - spender's secret keys and recipient's public key (a * B, sender side)
 *    - spender's public keys and recipient's secret key (A * b, recipient side)
 *  With this result, the necessary key material for ultimately creating/scanning
 *  or spending Silent Payments outputs can be determined.
 *
 *  Note that this module is _not_ a full implementation of BIP352, as it
 *  inherently doesn't deal with higher-level concepts like addresses, output
 *  script types or transactions. The intent is to provide a module for
 *  abstracting away the elliptic-curve operations required for the protocol. For
 *  any wallet software already using libsecp256k1, this API should provide all
 *  the functions needed for a Silent Payments implementation without requiring
 *  any further elliptic-curve operations from the wallet.
 */


/** The data from a single recipient address
 *
 *  This struct serves as an input argument to `silentpayments_sender_create_outputs`.
 *
 *  `index` must be set to the position (starting with 0) of this recipient in the
 *  `recipients` array passed to `silentpayments_sender_create_outputs`. It is
 *  used to map the returned generated outputs back to the original recipient.
 *
 *  Note:
 *  The spend public key named `spend_pubkey` may have been optionally tweaked with
 *  a label by the recipient. Whether `spend_pubkey` has actually been tagged with
 *  a label is irrelevant for the sender. As a documentation convention in this API,
 *  `unlabeled_spend_pubkey` is used to indicate when the unlabeled spend public must
 *  be used.
 */
typedef struct secp256k1_silentpayments_recipient {
    secp256k1_pubkey scan_pubkey;
    secp256k1_pubkey spend_pubkey;
    size_t index;
} secp256k1_silentpayments_recipient;

/** Create Silent Payments outputs for recipient(s).
 *
 *  Given a list of n secret keys a_1...a_n (one for each Silent Payments
 *  eligible input to spend), a serialized outpoint, and a list of recipients,
 *  create the taproot outputs. Inputs with conditional branches or multiple
 *  public keys are excluded from Silent Payments eligible inputs; see BIP352
 *  for more information.
 *
 *  `outpoint_smallest36` refers to the smallest outpoint lexicographically
 *  from the transaction inputs (both Silent Payments eligible and non-eligible
 *  inputs). This value MUST be the smallest outpoint out of all of the
 *  transaction inputs, otherwise the recipient will be unable to find the
 *  payment. Determining the smallest outpoint from the list of transaction
 *  inputs is the responsibility of the caller. It is strongly recommended
 *  that implementations ensure they are doing this correctly by using the
 *  test vectors from BIP352.
 *
 *  When creating more than one generated output, all of the generated outputs
 *  MUST be included in the final transaction. Dropping any of the generated
 *  outputs from the final transaction may make all or some of the outputs
 *  unfindable by the recipient.
 *
 *  Returns: 1 if creation of outputs was successful.
 *           0 on failure. This is expected only with an adversarially chosen
 *           recipient spend key. Specifically, failure occurs when:
 *             - Input secret keys sum to 0 or the negation of a spend key
 *               (negligible probability if at least one of the input secret
 *               keys is uniformly random and independent of all other keys)
 *             - A hash output is not a valid scalar (negligible probability
 *               per hash evaluation)
 *
 *  Args:                ctx: pointer to a context object
 *                            (not secp256k1_context_static).
 *  Out:   generated_outputs: pointer to an array of pointers to xonly public keys,
 *                            one per recipient.
 *                            The outputs are ordered to match the original
 *                            ordering of the recipient objects, i.e.,
 *                            `generated_outputs[0]` is the generated output
 *                            for the `_silentpayments_recipient` object with
 *                            index = 0.
 *  In:           recipients: pointer to an array of pointers to Silent Payments
 *                            recipients, where each recipient is a scan public
 *                            key, a spend public key, and an index indicating
 *                            its position in the original ordering. The
 *                            recipient array will be grouped by scan public key
 *                            in place (as specified in BIP0352), but generated
 *                            outputs are saved in the `generated_outputs` array
 *                            to match the original ordering (using the index
 *                            field). This ensures the caller is able to match
 *                            the generated outputs to the correct Silent
 *                            Payments addresses. The same recipient can be
 *                            passed multiple times to create multiple outputs
 *                            for the same recipient.
 *              n_recipients: the size of the recipients array.
 *       outpoint_smallest36: serialized (36-byte) smallest outpoint
 *                            (lexicographically) from the transaction inputs
 *           taproot_seckeys: pointer to an array of pointers to taproot
 *                            keypair inputs (can be NULL if no secret keys
 *                            of taproot inputs are used)
 *         n_taproot_seckeys: the size of taproot_seckeys array.
 *             plain_seckeys: pointer to an array of pointers to 32-byte
 *                            secret keys of non-taproot inputs (can be NULL
 *                            if no secret keys of non-taproot inputs are
 *                            used)
 *           n_plain_seckeys: the size of the plain_seckeys array.
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_sender_create_outputs(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey **generated_outputs,
    const secp256k1_silentpayments_recipient **recipients,
    size_t n_recipients,
    const unsigned char *outpoint_smallest36,
    const secp256k1_keypair * const *taproot_seckeys,
    size_t n_taproot_seckeys,
    const unsigned char * const *plain_seckeys,
    size_t n_plain_seckeys
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(5);

/** Create Silent Payments label tweak and label.
 *
 *  Given a recipient's 32 byte scan key and a label integer m, calculate the
 *  corresponding label tweak and label:
 *
 *      label_tweak = hash(scan_key || m)
 *            label = label_tweak * G
 *
 *  Returns: 1 if label tweak and label creation was successful.
 *           0 if hash output label_tweak32 is not valid scalar (negligible
 *             probability per hash evaluation).
 *
 *  Args:                ctx: pointer to a context object
 *                            (not secp256k1_context_static)
 *  Out:               label: pointer to the resulting label public key
 *             label_tweak32: pointer to the 32 byte label tweak
 *  In:           scan_key32: pointer to the recipient's 32 byte scan key
 *                         m: integer for the m-th label (0 is used for change outputs)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_recipient_create_label(
    const secp256k1_context *ctx,
    secp256k1_pubkey *label,
    unsigned char *label_tweak32,
    const unsigned char *scan_key32,
    uint32_t m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payments labeled spend public key.
 *
 *  Given a recipient's spend public key and a label, calculate the
 *  corresponding labeled spend public key:
 *
 *      labeled_spend_pubkey = unlabeled_spend_pubkey + label
 *
 *  The result is used by the recipient to create a Silent Payments address,
 *  consisting of the serialized and concatenated scan public key and
 *  (labeled) spend public key.
 *
 *  Returns: 1 if labeled spend public key creation was successful.
 *           0 if spend pubkey and label sum to zero (negligible probability for
 *             labels created according to BIP352).
 *
 *  Args:                    ctx: pointer to a context object
 *  Out:    labeled_spend_pubkey: pointer to the resulting labeled spend public key
 *  In:   unlabeled_spend_pubkey: pointer to the recipient's unlabeled spend public key
 *                         label: pointer to the recipient's label public key
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
    const secp256k1_context *ctx,
    secp256k1_pubkey *labeled_spend_pubkey,
    const secp256k1_pubkey *unlabeled_spend_pubkey,
    const secp256k1_pubkey *label
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */
