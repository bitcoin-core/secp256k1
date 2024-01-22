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
 *  or spending Silent Payment outputs can be determined.
 *
 *  Note that this module is _not_ a full implementation of BIP352, as it
 *  inherently doesn't deal with higher-level concepts like addresses, output
 *  script types or transactions. The intent is to provide a module for
 *  abstracting away the elliptic-curve operations required for the protocol. For
 *  any wallet software already using libsecp256k1, this API should provide all
 *  the functions needed for a Silent Payments implementation without requiring
 *  any further elliptic-curve operations from the wallet.
 */

/** This struct serves as an input parameter for passing the silent payment
 *  address data to `silentpayments_sender_create_outputs`.
 *
 *  The index field is for when more than one address is being sent to in
 *  a transaction. Index is set to the position of this recipient in the
 *  `recipients` array passed to `silentpayments_sender_create_outputs`
 *  and used to return the generated outputs matching the original ordering.
 *
 *  The spend public key field is named `labeled_spend_pubkey` to indicate this
 *  spend public key may be tweaked with an optional label. This is not relevant
 *  for the sender and is purely a documentation convention to differentiate
 *  between other uses of `spend_pubkey` in this API, where it is meant to refer
 *  to the unlabeled spend public key.
 */
typedef struct {
    secp256k1_pubkey scan_pubkey;
    secp256k1_pubkey labeled_spend_pubkey;
    size_t index;
} secp256k1_silentpayments_recipient;

/** Create Silent Payment outputs for recipient(s).
 *
 *  Given a list of n secret keys a_1...a_n (one for each silent payment
 *  eligible input to spend), a serialized outpoint, and a list of recipients,
 *  create the taproot outputs.
 *
 *  `outpoint_smallest` refers to the smallest outpoint lexicographically
 *  from the transaction inputs (both silent payments eligible and non-eligible
 *  inputs). This value MUST be the smallest outpoint out of all of the
 *  transaction inputs, otherwise the recipient will be unable to find the
 *  payment. Determining the smallest outpoint from the list of transaction
 *  inputs is the responsibility of the caller. It is strongly recommended
 *  that implementations ensure they are doing this correctly by using the
 *  test vectors from BIP352.
 *
 *  If necessary, the secret keys are negated to enforce the right y-parity.
 *  For that reason, the secret keys have to be passed in via two different
 *  parameter pairs, depending on whether the seckeys correspond to x-only
 *  outputs or not.
 *
 *  Returns: 1 if creation of outputs was successful. 0 if an error occurred.
 *  Args:                ctx: pointer to a context object
 *  Out:   generated_outputs: pointer to an array of pointers to xonly pubkeys,
 *                            one per recipient.
 *                            The outputs here are sorted by the index value
 *                            provided in the recipient objects.
 *  In:           recipients: pointer to an array of pointers to silent payment
 *                            recipients, where each recipient is a scan public
 *                            key, a spend public key, and an index indicating
 *                            its position in the original ordering. The
 *                            recipient array will be sorted in place, but
 *                            generated outputs are saved in the
 *                            `generated_outputs` array to match the ordering
 *                            from the index field. This ensures the caller is
 *                            able to match the generated outputs to the
 *                            correct silent payment addresses. The same
 *                            recipient can be passed multiple times to create
 *                            multiple outputs for the same recipient.
 *              n_recipients: the number of recipients. This is equal to the
 *                            total number of outputs to be generated as each
 *                            recipient may passed multiple times to generate
 *                            multiple outputs for the same recipient
 *         outpoint_smallest: serialized (36-byte) smallest outpoint
 *                            (lexicographically) from the transaction inputs
 *           taproot_seckeys: pointer to an array of pointers to taproot
 *                            keypair inputs (can be NULL if no secret keys
 *                            of taproot inputs are used)
 *         n_taproot_seckeys: the number of sender's taproot input secret keys
 *             plain_seckeys: pointer to an array of pointers to 32-byte
 *                            secret keys of non-taproot inputs (can be NULL
 *                            if no secret keys of non-taproot inputs are
 *                            used)
 *           n_plain_seckeys: the number of sender's non-taproot input secret
 *                            keys
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

/** Create Silent Payment label tweak and label.
 *
 *  Given a recipient's 32 byte scan key b_scan and a label integer m, calculate the
 *  corresponding label tweak and label:
 *
 *  label_tweak = hash(b_scan || m)
 *        label = label_tweak * G
 *
 *  Returns: 1 if label tweak and label creation was successful.
 *           0 if an error occurred.
 *  Args:                ctx: pointer to a context object
 *  Out:               label: pointer to the resulting label public key
 *             label_tweak32: pointer to the 32 byte label tweak
 *  In: recipient_scan_key32: pointer to the recipient's 32 byte scan key
 *                         m: label integer (0 is used for change outputs)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_recipient_create_label(
    const secp256k1_context *ctx,
    secp256k1_pubkey *label,
    unsigned char *label_tweak32,
    const unsigned char *recipient_scan_key32,
    const uint32_t m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payment labeled spend public key.
 *
 *  Given a recipient's spend public key B_spend and a label, calculate the
 *  corresponding labeled spend public key:
 *
 *  B_m = B_spend + label
 *
 *  The result is used by the recipient to create a Silent Payment address,
 *  consisting of the serialized and concatenated scan public key and
 *  (labeled) spend public key each.
 *
 *  Returns: 1 if labeled spend public key creation was successful.
 *           0 if an error occurred.
 *  Args:                    ctx: pointer to a context object
 *  Out:    labeled_spend_pubkey: pointer to the resulting labeled spend
 *                                public key
 *  In:   recipient_spend_pubkey: pointer to the recipient's spend pubkey
 *                         label: pointer to the the recipient's label public
 *                                key
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(
    const secp256k1_context *ctx,
    secp256k1_pubkey *labeled_spend_pubkey,
    const secp256k1_pubkey *recipient_spend_pubkey,
    const secp256k1_pubkey *label
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */
