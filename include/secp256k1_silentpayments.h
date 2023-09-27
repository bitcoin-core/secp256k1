#ifndef SECP256K1_SILENTPAYMENTS_H
#define SECP256K1_SILENTPAYMENTS_H

#include "secp256k1.h"
#include "secp256k1_extrakeys.h"

#ifdef __cplusplus
extern "C" {
#endif

/* This module provides an implementation for the ECC related parts of
 * Silent Payments, as specified in BIP352. This particularly involves
 * the creation of input tweak data by summing up private or public keys
 * and the derivation of a shared secret using Elliptic Curve Diffie-Hellman.
 * Combined are either:
 *   - spender's private keys and receiver's public key (a * B, sender side)
 *   - spender's public keys and receiver's private key (A * b, receiver side)
 * With this result, the necessary key material for ultimately creating/scanning
 * or spending Silent Payment outputs can be determined.
 *
 * Note that this module is _not_ a full implementation of BIP352, as it
 * inherently doesn't deal with higher-level concepts like addresses, output
 * script types or transactions. The intent is to provide cryptographical
 * helpers for low-level calculations that are most error-prone to custom
 * implementations (e.g. enforcing the right y-parity for key material, ECDH
 * calculation etc.). For any wallet software already using libsecp256k1, this
 * API should provide all the functions needed for a Silent Payments
 * implementation without the need for any further manual elliptic-curve
 * operations.
 */

/** Create Silent Payment tweak data from input private keys.
 *
 * Given a list of n private keys a_1...a_n (one for each silent payment
 * eligible input to spend) and a serialized outpoint_smallest, compute
 * the corresponding input private keys tweak data:
 *
 * a_sum = a_1 + a_2 + ... + a_n
 * input_hash = hash(outpoint_smallest || (a_sum * G))
 *
 * If necessary, the private keys are negated to enforce the right y-parity.
 * For that reason, the private keys have to be passed in via two different parameter
 * pairs, depending on whether they were used for creating taproot outputs or not.
 * The resulting data is needed to create a shared secret for the sender side.
 *
 *  Returns: 1 if shared secret creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:                 a_sum: pointer to the resulting 32-byte private key sum
 *                  input_hash: pointer to the resulting 32-byte input hash
 *  In:          plain_seckeys: pointer to an array of pointers to 32-byte private keys
 *                              of non-taproot inputs (can be NULL if no private keys of
 *                              non-taproot inputs are used)
 *             n_plain_seckeys: the number of sender's non-taproot input private keys
 *             taproot_seckeys: pointer to an array of pointers to 32-byte private keys
 *                              of taproot inputs (can be NULL if no private keys of
 *                              taproot inputs are used)
 *           n_taproot_seckeys: the number of sender's taproot input private keys
 *         outpoint_smallest36: serialized smallest outpoint
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_private_tweak_data(
    const secp256k1_context *ctx,
    unsigned char *a_sum,
    unsigned char *input_hash,
    const unsigned char * const *plain_seckeys,
    size_t n_plain_seckeys,
    const unsigned char * const *taproot_seckeys,
    size_t n_taproot_seckeys,
    const unsigned char *outpoint_smallest36
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(8);

/** Create Silent Payment tweak data from input public keys.
 *
 * Given a list of n public keys A_1...A_n (one for each silent payment
 * eligible input to spend) and a serialized outpoint_smallest, compute
 * the corresponding input public keys tweak data:
 *
 * A_sum = A_1 + A_2 + ... + A_n
 * input_hash = hash(outpoint_lowest || A_sum)
 *
 * The public keys have to be passed in via two different parameter pairs,
 * one for regular and one for x-only public keys, in order to avoid the need
 * of users converting to a common pubkey format before calling this function.
 * The resulting data is needed to create a shared secret for the receiver's side.
 *
 *  Returns: 1 if tweak data creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:                 A_sum: pointer to the resulting public keys sum
 *                  input_hash: pointer to the resulting 32-byte input hash
 *  In:          plain_pubkeys: pointer to an array of pointers to non-taproot
 *                              public keys (can be NULL if no non-taproot inputs are used)
 *             n_plain_pubkeys: the number of non-taproot input public keys
 *               xonly_pubkeys: pointer to an array of pointers to taproot x-only
 *                              public keys (can be NULL if no taproot inputs are used)
 *             n_xonly_pubkeys: the number of taproot input public keys
 *         outpoint_smallest36: serialized smallest outpoint
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_public_tweak_data(
    const secp256k1_context *ctx,
    secp256k1_pubkey *A_sum,
    unsigned char *input_hash,
    const secp256k1_pubkey * const *plain_pubkeys,
    size_t n_plain_pubkeys,
    const secp256k1_xonly_pubkey * const *xonly_pubkeys,
    size_t n_xonly_pubkeys,
    const unsigned char *outpoint_smallest36
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(8);

/** Create Silent Payment tweaked public key from public tweak data.
 *
 * Given public tweak data (public keys sum and input hash), calculate the
 * corresponding tweaked public key:
 *
 * A_tweaked = input_hash * A_sum
 *
 * The resulting data is useful for light clients and silent payment indexes.
 *
 *  Returns: 1 if tweaked public key creation was successful. 0 if an error occured.
 *  Args:              ctx: pointer to a context object
 *  Out:         A_tweaked: pointer to the resulting tweaked public key
 *  In:              A_sum: pointer to the public keys sum
 *              input_hash: pointer to the 32-byte input hash
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_tweaked_pubkey(
    const secp256k1_context *ctx,
    secp256k1_pubkey *A_tweaked,
    const secp256k1_pubkey *A_sum,
    const unsigned char *input_hash
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payment shared secret.
 *
 * Given a public component Pub, a private component sec and an input_hash,
 * calculate the corresponding shared secret using ECDH:
 *
 * shared_secret = (sec * input_hash) * Pub
 *
 * What the components should be set to depends on the role of the caller.
 * For the sender side, the public component is set the recipient's scan public key
 * B_scan, and the private component is set to the input's private keys sum:
 *
 * shared_secret = (a_sum * input_hash) * B_scan   [Sender]
 *
 * For the receiver side, the public component is set to the input's public keys sum,
 * and the private component is set to the receiver's scan private key:
 *
 * shared_secret = (b_scan * input_hash) * A_sum   [Receiver, Full node scenario]
 *
 * In the "light client" scenario for receivers, the public component is already
 * tweaked with the input hash: A_tweaked = input_hash * A_sum
 * In this case, the input_hash parameter should be set to NULL, to signal that
 * no further tweaking should be done before the ECDH:
 *
 * shared_secret = b_scan * A_tweaked   [Receiver, Light client scenario]
 *
 * The resulting shared secret is needed as input for creating silent payments
 * outputs belonging to the same receiver scan public key.
 *
 *  Returns: 1 if shared secret creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:       shared_secret33: pointer to the resulting 33-byte shared secret
 *  In:       public_component: pointer to the public component
 *           private_component: pointer to 32-byte private component
 *                  input_hash: pointer to 32-byte input hash (can be NULL if the
 *                              public component is already tweaked with the input hash)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_shared_secret(
    const secp256k1_context *ctx,
    unsigned char *shared_secret33,
    const secp256k1_pubkey *public_component,
    const unsigned char *secret_component,
    const unsigned char *input_hash
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payment label tweak and label.
 *
 *  Given a recipient's scan private key b_scan and a label integer m, calculate
 *  the corresponding label tweak and label:
 *
 *  label_tweak = hash(b_scan || m)
 *  label = label_tweak * G
 *
 *  Returns: 1 if label tweak and label creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out:           label_tweak: pointer to the resulting label tweak
 *   In:  receiver_scan_seckey: pointer to the receiver's scan private key
 *                           m: label integer (0 is used for change outputs)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_label_tweak(
    const secp256k1_context *ctx,
    secp256k1_pubkey *label,
    unsigned char *label_tweak32,
    const unsigned char *receiver_scan_seckey,
    unsigned int m
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payment labelled spend public key.
 *
 *  Given a recipient's spend public key B_spend and a label, calculate
 *  the corresponding serialized labelled spend public key:
 *
 *  B_m = B_spend + label
 *
 *  The result is used by the receiver to create a Silent Payment address, consisting
 *  of the serialized and concatenated scan public key and (labelled) spend public key each.
 *
 *  Returns: 1 if labelled spend public key creation was successful. 0 if an error occured.
 *  Args:                  ctx: pointer to a context object
 *  Out: l_addr_spend_pubkey33: pointer to the resulting labelled spend public key
 *   In: receiver_spend_pubkey: pointer to the receiver's spend pubkey
 *                       label: pointer to the the receiver's label
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_create_address_spend_pubkey(
    const secp256k1_context *ctx,
    unsigned char *l_addr_spend_pubkey33,
    const secp256k1_pubkey *receiver_spend_pubkey,
    const secp256k1_pubkey *label
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

/** Create Silent Payment output public key (for sender).
 *
 *  Given a shared_secret, a recipient's spend public key B_spend, and
 *  an output counter k, calculate the corresponding output public key:
 *
 *  P_output_xonly = B_spend + hash(shared_secret || ser_32(k)) * G
 *
 *  Returns: 1 if output creation was successful. 0 if an error occured.
 *  Args:               ctx: pointer to a context object
 *  Out:     P_output_xonly: pointer to the resulting output x-only pubkey
 *  In:     shared_secret33: shared secret, derived from either sender's
 *                           or receiver's perspective with routines from above
 *    receiver_spend_pubkey: pointer to the receiver's spend pubkey
 *                        k: output counter (usually set to 0, should be increased for
 *                           every additional output to the same recipient)
 */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_silentpayments_sender_create_output_pubkey(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey *P_output_xonly,
    const unsigned char *shared_secret33,
    const secp256k1_pubkey *receiver_spend_pubkey,
    unsigned int k
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3) SECP256K1_ARG_NONNULL(4);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SILENTPAYMENTS_H */
