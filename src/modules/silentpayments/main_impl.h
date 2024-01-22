/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H
#define SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_silentpayments.h"

/** Sort an array of silent payment recipients. This is used to group recipients by scan pubkey to
 *  ensure the correct values of k are used when creating multiple outputs for a recipient. */
static int secp256k1_silentpayments_recipient_sort_cmp(const void* pk1, const void* pk2, void *ctx) {
    return secp256k1_ec_pubkey_cmp((secp256k1_context *)ctx,
        &(*(const secp256k1_silentpayments_recipient **)pk1)->scan_pubkey,
        &(*(const secp256k1_silentpayments_recipient **)pk2)->scan_pubkey
    );
}

static void secp256k1_silentpayments_recipient_sort(const secp256k1_context* ctx, const secp256k1_silentpayments_recipient **recipients, size_t n_recipients) {

    /* Suppress wrong warning (fixed in MSVC 19.33) */
    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(push)
    #pragma warning(disable: 4090)
    #endif

    secp256k1_hsort(recipients, n_recipients, sizeof(*recipients), secp256k1_silentpayments_recipient_sort_cmp, (void *)ctx);

    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(pop)
    #endif
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/Inputs". */
static void secp256k1_silentpayments_sha256_init_inputs(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0xd4143ffcul;
    hash->s[1] = 0x012ea4b5ul;
    hash->s[2] = 0x36e21c8ful;
    hash->s[3] = 0xf7ec7b54ul;
    hash->s[4] = 0x4dd4e2acul;
    hash->s[5] = 0x9bcaa0a4ul;
    hash->s[6] = 0xe244899bul;
    hash->s[7] = 0xcd06903eul;

    hash->bytes = 64;
}

static void secp256k1_silentpayments_calculate_input_hash(unsigned char *input_hash, const unsigned char *outpoint_smallest36, secp256k1_ge *pubkey_sum) {
    secp256k1_sha256 hash;
    unsigned char pubkey_sum_ser[33];
    size_t len;
    int ret;

    secp256k1_silentpayments_sha256_init_inputs(&hash);
    secp256k1_sha256_write(&hash, outpoint_smallest36, 36);
    ret = secp256k1_eckey_pubkey_serialize(pubkey_sum, pubkey_sum_ser, &len, 1);
    VERIFY_CHECK(ret && len == sizeof(pubkey_sum_ser));
    (void)ret;
    secp256k1_sha256_write(&hash, pubkey_sum_ser, sizeof(pubkey_sum_ser));
    secp256k1_sha256_finalize(&hash, input_hash);
}

static void secp256k1_silentpayments_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const secp256k1_scalar *secret_component, const secp256k1_ge *public_component) {
    secp256k1_gej ss_j;
    secp256k1_ge ss;
    size_t len;
    int ret;

    /* Compute shared_secret = tweaked_secret_component * Public_component */
    secp256k1_ecmult_const(&ss_j, public_component, secret_component);
    secp256k1_ge_set_gej(&ss, &ss_j);
    secp256k1_declassify(ctx, &ss, sizeof(ss));
    /* This can only fail if the shared secret is the point at infinity, which should be
     * impossible at this point, considering we have already validated the public key and
     * the secret key being used
     */
    ret = secp256k1_eckey_pubkey_serialize(&ss, shared_secret33, &len, 1);
    VERIFY_CHECK(ret && len == 33);
    (void)ret;
    /* While not technically "secret" data, explicitly clear the shared secret since leaking this would allow an attacker
     * to identify the resulting transaction as a silent payments transaction and potentially link the transaction
     * back to the silent payment address
     */
    secp256k1_ge_clear(&ss);
    secp256k1_gej_clear(&ss_j);
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/SharedSecret". */
static void secp256k1_silentpayments_sha256_init_sharedsecret(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0x88831537ul;
    hash->s[1] = 0x5127079bul;
    hash->s[2] = 0x69c2137bul;
    hash->s[3] = 0xab0303e6ul;
    hash->s[4] = 0x98fa21faul;
    hash->s[5] = 0x4a888523ul;
    hash->s[6] = 0xbd99daabul;
    hash->s[7] = 0xf25e5e0aul;

    hash->bytes = 64;
}

static void secp256k1_silentpayments_create_t_k(secp256k1_scalar *t_k_scalar, const unsigned char *shared_secret33, uint32_t k) {
    secp256k1_sha256 hash;
    unsigned char hash_ser[32];
    unsigned char k_serialized[4];
    int overflow = 0;

    /* Compute t_k = hash(shared_secret || ser_32(k))  [sha256 with tag "BIP0352/SharedSecret"] */
    secp256k1_silentpayments_sha256_init_sharedsecret(&hash);
    secp256k1_sha256_write(&hash, shared_secret33, 33);
    secp256k1_write_be32(k_serialized, k);
    secp256k1_sha256_write(&hash, k_serialized, sizeof(k_serialized));
    secp256k1_sha256_finalize(&hash, hash_ser);
    secp256k1_scalar_set_b32(t_k_scalar, hash_ser, &overflow);
    VERIFY_CHECK(!overflow);
    VERIFY_CHECK(!secp256k1_scalar_is_zero(t_k_scalar));
    /* While not technically "secret" data, explicitly clear hash_ser since leaking this would allow an attacker
     * to identify the resulting transaction as a silent payments transaction and potentially link the transaction
     * back to the silent payment address
     */
    secp256k1_memclear(hash_ser, sizeof(hash_ser));
}

static int secp256k1_silentpayments_create_output_pubkey(const secp256k1_context *ctx, secp256k1_xonly_pubkey *P_output_xonly, const unsigned char *shared_secret33, const secp256k1_pubkey *recipient_labeled_spend_pubkey, uint32_t k) {
    secp256k1_ge P_output_ge;
    secp256k1_scalar t_k_scalar;
    int ret;

    /* Calculate and return P_output_xonly = B_spend + t_k * G
     * This will fail if B_spend is the point at infinity or if
     * B_spend + t_k*G is the point at infinity.
     */
    secp256k1_silentpayments_create_t_k(&t_k_scalar, shared_secret33, k);
    if (!secp256k1_pubkey_load(ctx, &P_output_ge, recipient_labeled_spend_pubkey)) {
        secp256k1_scalar_clear(&t_k_scalar);
        return 0;
    }
    ret = secp256k1_eckey_pubkey_tweak_add(&P_output_ge, &t_k_scalar);
    /* tweak add only fails if t_k_scalar is equal to the dlog of P_output_ge, but t_k_scalar is the output of a collision resistant hash function. */
    /* TODO: consider declassify ret */
    /* TODO: but we don't want to imply this can never happen */
    VERIFY_CHECK(ret);
#ifndef VERIFY
    (void) ret;
#endif
    secp256k1_xonly_pubkey_save(P_output_xonly, &P_output_ge);

    /* While not technically "secret" data, explicitly clear t_k since leaking this would allow an attacker
     * to identify the resulting transaction as a silent payments transaction and potentially link the transaction
     * back to the silent payment address
     */
    secp256k1_scalar_clear(&t_k_scalar);
    return 1;
}

int secp256k1_silentpayments_sender_create_outputs(
    const secp256k1_context *ctx,
    secp256k1_xonly_pubkey **generated_outputs,
    const secp256k1_silentpayments_recipient **recipients,
    size_t n_recipients,
    const unsigned char *outpoint_smallest36,
    const secp256k1_keypair * const *taproot_seckeys,
    size_t n_taproot_seckeys,
    const unsigned char * const *plain_seckeys,
    size_t n_plain_seckeys
) {
    size_t i, k;
    secp256k1_scalar a_sum_scalar, addend, input_hash_scalar;
    secp256k1_ge A_sum_ge;
    secp256k1_gej A_sum_gej;
    unsigned char input_hash[32];
    unsigned char shared_secret[33];
    secp256k1_silentpayments_recipient last_recipient;
    int overflow = 0;
    int ret;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(generated_outputs != NULL);
    ARG_CHECK(recipients != NULL);
    ARG_CHECK(n_recipients > 0);
    ARG_CHECK((plain_seckeys != NULL) || (taproot_seckeys != NULL));
    if (taproot_seckeys != NULL) {
        ARG_CHECK(n_taproot_seckeys > 0);
    } else {
        ARG_CHECK(n_taproot_seckeys == 0);
    }
    if (plain_seckeys != NULL) {
        ARG_CHECK(n_plain_seckeys > 0);
    } else {
        ARG_CHECK(n_plain_seckeys == 0);
    }
    ARG_CHECK(outpoint_smallest36 != NULL);
    /* ensure the index field is set correctly */
    for (i = 0; i < n_recipients; i++) {
        ARG_CHECK(recipients[i]->index == i);
    }

    /* Compute input private keys sum: a_sum = a_1 + a_2 + ... + a_n */
    a_sum_scalar = secp256k1_scalar_zero;
    for (i = 0; i < n_plain_seckeys; i++) {
        ret = secp256k1_scalar_set_b32_seckey(&addend, plain_seckeys[i]);
        secp256k1_declassify(ctx, &ret, sizeof(ret));
        if (!ret) {
            secp256k1_scalar_clear(&addend);
            secp256k1_scalar_clear(&a_sum_scalar);
            return 0;
        }
        secp256k1_scalar_add(&a_sum_scalar, &a_sum_scalar, &addend);
    }
    /* private keys used for taproot outputs have to be negated if they resulted in an odd point */
    for (i = 0; i < n_taproot_seckeys; i++) {
        secp256k1_ge addend_point;
        ret = secp256k1_keypair_load(ctx, &addend, &addend_point, taproot_seckeys[i]);
        secp256k1_declassify(ctx, &ret, sizeof(ret));
        if (!ret) {
            secp256k1_scalar_clear(&addend);
            secp256k1_scalar_clear(&a_sum_scalar);
            return 0;
        }
        secp256k1_declassify(ctx, &ret, sizeof(ret));
        if (secp256k1_fe_is_odd(&addend_point.y)) {
            secp256k1_scalar_negate(&addend, &addend);
        }
        secp256k1_scalar_add(&a_sum_scalar, &a_sum_scalar, &addend);
    }
    /* If there are any failures in loading/summing up the secret keys, fail early */
    ret = secp256k1_scalar_is_zero(&a_sum_scalar);
    secp256k1_declassify(ctx, &ret, sizeof(ret));
    if (ret) {
        secp256k1_scalar_clear(&addend);
        secp256k1_scalar_clear(&a_sum_scalar);
        return 0;
    } else {
        /* Clear the addend variable as this is no longer needed at this point
         * and contains secret data. This saves from needing to remember to clear
         * this variable from multiple places below */
        secp256k1_scalar_clear(&addend);
    }
    /* Compute input_hash = hash(outpoint_L || (a_sum * G)) */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &A_sum_gej, &a_sum_scalar);
    secp256k1_ge_set_gej(&A_sum_ge, &A_sum_gej);
    /* TODO: comment */
    secp256k1_declassify(ctx, &A_sum_ge, sizeof(A_sum_ge));

    /* Calculate the input hash and tweak a_sum, i.e., a_sum_tweaked = a_sum * input_hash
     * This should fail if input hash is greater than the curve order, but this is stastically improbable so
     * we only do a verify_check here.
     */
    secp256k1_silentpayments_calculate_input_hash(input_hash, outpoint_smallest36, &A_sum_ge);
    secp256k1_scalar_set_b32(&input_hash_scalar, input_hash, &overflow);
    VERIFY_CHECK(!overflow);
    secp256k1_scalar_mul(&a_sum_scalar, &a_sum_scalar, &input_hash_scalar);
    /* _recipient_sort sorts the array of recipients in place by their scan public keys (lexicographically).
     * This ensures that all recipients with the same scan public key are grouped together, as specified in BIP0352.
     *
     * More specifically, this ensures `k` is incremented from 0 to the number of requested outputs for each recipient group,
     * where a recipient group is all addresses with the same scan public key.
     */
    secp256k1_silentpayments_recipient_sort(ctx, recipients, n_recipients);
    last_recipient = *recipients[0];
    k = 0;
    for (i = 0; i < n_recipients; i++) {
        if ((i == 0) || (secp256k1_ec_pubkey_cmp(ctx, &last_recipient.scan_pubkey, &recipients[i]->scan_pubkey) != 0)) {
            /* If we are on a different scan pubkey, its time to recreate the shared secret and reset k to 0.
             * It's very unlikely the scan public key is invalid by this point, since this means the caller would
             * have created the _silentpayments_recipient object incorrectly, but just to be sure we still check that
             * the public key is valid.
             */
            secp256k1_ge pk;
            if (!secp256k1_pubkey_load(ctx, &pk, &recipients[i]->scan_pubkey)) {
                secp256k1_scalar_clear(&a_sum_scalar);
                return 0;
            }
            secp256k1_silentpayments_create_shared_secret(ctx, shared_secret, &a_sum_scalar, &pk);
            k = 0;
        }
        if (!secp256k1_silentpayments_create_output_pubkey(ctx, generated_outputs[recipients[i]->index], shared_secret, &recipients[i]->labeled_spend_pubkey, k)) {
            secp256k1_scalar_clear(&a_sum_scalar);
            return 0;
        }
        k++;
        last_recipient = *recipients[i];
    }
    /* Explicitly clear variables containing secret data */
    secp256k1_scalar_clear(&a_sum_scalar);

    /* While technically not "secret data," explicitly clear the shared secret since leaking this
     * could result in a third party being able to identify the transaction as a silent payments transaction
     * and potentially link the transaction back to a silent payment address
     */
    secp256k1_memclear(&shared_secret, sizeof(shared_secret));
    return 1;
}

/** Set hash state to the BIP340 tagged hash midstate for "BIP0352/Label". */
static void secp256k1_silentpayments_sha256_init_label(secp256k1_sha256* hash) {
    secp256k1_sha256_initialize(hash);
    hash->s[0] = 0x26b95d63ul;
    hash->s[1] = 0x8bf1b740ul;
    hash->s[2] = 0x10a5986ful;
    hash->s[3] = 0x06a387a5ul;
    hash->s[4] = 0x2d1c1c30ul;
    hash->s[5] = 0xd035951aul;
    hash->s[6] = 0x2d7f0f96ul;
    hash->s[7] = 0x29e3e0dbul;

    hash->bytes = 64;
}

int secp256k1_silentpayments_recipient_create_label(const secp256k1_context *ctx, secp256k1_pubkey *label, unsigned char *label_tweak32, const unsigned char *recipient_scan_key32, const uint32_t m) {
    secp256k1_sha256 hash;
    unsigned char m_serialized[4];

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(label != NULL);
    ARG_CHECK(label_tweak32 != NULL);
    ARG_CHECK(recipient_scan_key32 != NULL);

    /* Compute label_tweak = hash(ser_256(b_scan) || ser_32(m))  [sha256 with tag "BIP0352/Label"] */
    secp256k1_silentpayments_sha256_init_label(&hash);
    secp256k1_sha256_write(&hash, recipient_scan_key32, 32);
    secp256k1_write_be32(m_serialized, m);
    secp256k1_sha256_write(&hash, m_serialized, sizeof(m_serialized));
    secp256k1_sha256_finalize(&hash, label_tweak32);

    /* Compute label = label_tweak * G */
    return secp256k1_ec_pubkey_create(ctx, label, label_tweak32);
}

int secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(const secp256k1_context *ctx, secp256k1_pubkey *labeled_spend_pubkey, const secp256k1_pubkey *recipient_spend_pubkey, const secp256k1_pubkey *label) {
    secp256k1_ge B_m, label_addend;
    secp256k1_gej result_gej;
    secp256k1_ge result_ge;
    int ret;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(labeled_spend_pubkey != NULL);
    ARG_CHECK(recipient_spend_pubkey != NULL);
    ARG_CHECK(label != NULL);

    /* Calculate B_m = B_spend + label
     * If either the label or spend public key is an invalid public key,
     * return early
     */
    ret = secp256k1_pubkey_load(ctx, &B_m, recipient_spend_pubkey);
    ret &= secp256k1_pubkey_load(ctx, &label_addend, label);
    if (!ret) {
        return ret;
    }
    secp256k1_gej_set_ge(&result_gej, &B_m);
    secp256k1_gej_add_ge_var(&result_gej, &result_gej, &label_addend, NULL);
    if (secp256k1_gej_is_infinity(&result_gej)) {
        return 0;
    }

    secp256k1_ge_set_gej(&result_ge, &result_gej);
    secp256k1_pubkey_save(labeled_spend_pubkey, &result_ge);

    return 1;
}

#endif
