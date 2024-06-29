/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H
#define SECP256K1_MODULE_SILENTPAYMENTS_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_ecdh.h"
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

int secp256k1_silentpayments_recipient_sort(const secp256k1_context* ctx, const secp256k1_silentpayments_recipient **recipients, size_t n_recipients) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(recipients != NULL);

    /* Suppress wrong warning (fixed in MSVC 19.33) */
    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(push)
    #pragma warning(disable: 4090)
    #endif

    secp256k1_hsort(recipients, n_recipients, sizeof(*recipients), secp256k1_silentpayments_recipient_sort_cmp, (void *)ctx);

    #if defined(_MSC_VER) && (_MSC_VER < 1933)
    #pragma warning(pop)
    #endif

    return 1;
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
    size_t ser_size;
    int ser_ret;

    secp256k1_silentpayments_sha256_init_inputs(&hash);
    secp256k1_sha256_write(&hash, outpoint_smallest36, 36);
    ser_ret = secp256k1_eckey_pubkey_serialize(pubkey_sum, pubkey_sum_ser, &ser_size, 1);
    VERIFY_CHECK(ser_ret && ser_size == sizeof(pubkey_sum_ser));
    (void)ser_ret;
    secp256k1_sha256_write(&hash, pubkey_sum_ser, sizeof(pubkey_sum_ser));
    secp256k1_sha256_finalize(&hash, input_hash);
}

/* secp256k1_ecdh expects a hash function to be passed in or uses its default
 * hashing function. We don't want to hash the ECDH result yet (it will be
 * hashed later with a counter `k`), so we define a custom function which simply
 * returns the pubkey without hashing.
 */
static int secp256k1_silentpayments_ecdh_return_pubkey(unsigned char *output, const unsigned char *x32, const unsigned char *y32, void *data) {
    secp256k1_ge point;
    secp256k1_fe x, y;
    size_t ser_size;
    int ser_ret;

    (void)data;
    /* Parse point as group element */
    if (!secp256k1_fe_set_b32_limit(&x, x32) || !secp256k1_fe_set_b32_limit(&y, y32)) {
        return 0;
    }
    secp256k1_ge_set_xy(&point, &x, &y);

    /* Serialize as compressed pubkey */
    ser_ret = secp256k1_eckey_pubkey_serialize(&point, output, &ser_size, 1);
    VERIFY_CHECK(ser_ret && ser_size == 33);
    (void)ser_ret;

    return 1;
}

static int secp256k1_silentpayments_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const unsigned char *secret_component, const secp256k1_pubkey *public_component, const unsigned char *input_hash) {
    unsigned char tweaked_secret_component[32];
    /* Sanity check inputs */
    ARG_CHECK(shared_secret33 != NULL);
    memset(shared_secret33, 0, 33);
    ARG_CHECK(public_component != NULL);
    ARG_CHECK(secret_component != NULL);

    /* Tweak secret component with input hash, if available */
    memcpy(tweaked_secret_component, secret_component, 32);
    if (input_hash != NULL) {
        if (!secp256k1_ec_seckey_tweak_mul(ctx, tweaked_secret_component, input_hash)) {
            return 0;
        }
    }

    /* Compute shared_secret = tweaked_secret_component * Public_component */
    if (!secp256k1_ecdh(ctx, shared_secret33, public_component, tweaked_secret_component, secp256k1_silentpayments_ecdh_return_pubkey, NULL)) {
        return 0;
    }

    return 1;
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

static void secp256k1_silentpayments_create_t_k(secp256k1_scalar *t_k_scalar, const unsigned char *shared_secret33, unsigned int k) {
    secp256k1_sha256 hash;
    unsigned char hash_ser[32];
    unsigned char k_serialized[4];

    /* Compute t_k = hash(shared_secret || ser_32(k))  [sha256 with tag "BIP0352/SharedSecret"] */
    secp256k1_silentpayments_sha256_init_sharedsecret(&hash);
    secp256k1_sha256_write(&hash, shared_secret33, 33);
    secp256k1_write_be32(k_serialized, k);
    secp256k1_sha256_write(&hash, k_serialized, sizeof(k_serialized));
    secp256k1_sha256_finalize(&hash, hash_ser);
    secp256k1_scalar_set_b32(t_k_scalar, hash_ser, NULL);
}

static int secp256k1_silentpayments_create_output_pubkey(const secp256k1_context *ctx, secp256k1_xonly_pubkey *P_output_xonly, const unsigned char *shared_secret33, const secp256k1_pubkey *recipient_spend_pubkey, unsigned int k) {
    secp256k1_ge P_output_ge;
    secp256k1_scalar t_k_scalar;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(P_output_xonly != NULL);
    ARG_CHECK(shared_secret33 != NULL);
    ARG_CHECK(recipient_spend_pubkey != NULL);

    /* Calculate and return P_output_xonly = B_spend + t_k * G */
    secp256k1_silentpayments_create_t_k(&t_k_scalar, shared_secret33, k);
    secp256k1_pubkey_load(ctx, &P_output_ge, recipient_spend_pubkey);

    /* This will fail if B_spend + t_k*G is the point at infinity */
    if (!secp256k1_eckey_pubkey_tweak_add(&P_output_ge, &t_k_scalar)) {
        return 0;
    }
    secp256k1_xonly_pubkey_save(P_output_xonly, &P_output_ge);

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
    secp256k1_scalar a_sum_scalar, addend;
    secp256k1_ge A_sum_ge;
    secp256k1_gej A_sum_gej;
    unsigned char input_hash[32];
    unsigned char a_sum[32];
    unsigned char shared_secret[33];
    secp256k1_silentpayments_recipient last_recipient;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(generated_outputs != NULL);
    ARG_CHECK(recipients != NULL);
    ARG_CHECK(n_recipients >= 1);
    ARG_CHECK(plain_seckeys == NULL || n_plain_seckeys >= 1);
    ARG_CHECK(taproot_seckeys == NULL || n_taproot_seckeys >= 1);
    ARG_CHECK((plain_seckeys != NULL) || (taproot_seckeys != NULL));
    ARG_CHECK((n_plain_seckeys + n_taproot_seckeys) >= 1);
    ARG_CHECK(outpoint_smallest36 != NULL);
    /* ensure the index field is set correctly */
    for (i = 0; i < n_recipients; i++) {
        ARG_CHECK(recipients[i]->index == i);
    }

    /* Compute input private keys sum: a_sum = a_1 + a_2 + ... + a_n */
    a_sum_scalar = secp256k1_scalar_zero;
    for (i = 0; i < n_plain_seckeys; i++) {
        if (!secp256k1_scalar_set_b32_seckey(&addend, plain_seckeys[i])) {
            return 0;
        }
        secp256k1_scalar_add(&a_sum_scalar, &a_sum_scalar, &addend);
    }
    /* private keys used for taproot outputs have to be negated if they resulted in an odd point */
    for (i = 0; i < n_taproot_seckeys; i++) {
        secp256k1_ge addend_point;
        if (!secp256k1_keypair_load(ctx, &addend, &addend_point, taproot_seckeys[i])) {
            return 0;
        }
        if (secp256k1_fe_is_odd(&addend_point.y)) {
            secp256k1_scalar_negate(&addend, &addend);
        }

        secp256k1_scalar_add(&a_sum_scalar, &a_sum_scalar, &addend);
    }
    /* If the caller passes in seckeys that sum up to zero, there is nothing
     * we can do here except have the caller try again with different seckeys,
     * e.g. run coin selection again */
    if (secp256k1_scalar_is_zero(&a_sum_scalar)) {
        return 0;
    }
    secp256k1_scalar_get_b32(a_sum, &a_sum_scalar);

    /* Compute input_hash = hash(outpoint_L || (a_sum * G)) */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &A_sum_gej, &a_sum_scalar);
    secp256k1_ge_set_gej(&A_sum_ge, &A_sum_gej);
    secp256k1_silentpayments_calculate_input_hash(input_hash, outpoint_smallest36, &A_sum_ge);
    secp256k1_silentpayments_recipient_sort(ctx, recipients, n_recipients);
    last_recipient = *recipients[0];
    k = 0;
    for (i = 0; i < n_recipients; i++) {
        if ((secp256k1_ec_pubkey_cmp(ctx, &last_recipient.scan_pubkey, &recipients[i]->scan_pubkey) != 0) || (i == 0)) {
            /* if we are on a different scan pubkey, its time to recreate the the shared secret and reset k to 0 */
            if (!secp256k1_silentpayments_create_shared_secret(ctx, shared_secret, a_sum, &recipients[i]->scan_pubkey, input_hash)) {
                return 0;
            }
            k = 0;
        }
        if (!secp256k1_silentpayments_create_output_pubkey(ctx, generated_outputs[recipients[i]->index], shared_secret, &recipients[i]->spend_pubkey, k)) {
            return 0;
        }
        k++;
        last_recipient = *recipients[i];
    }
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

int secp256k1_silentpayments_recipient_create_label_tweak(const secp256k1_context *ctx, secp256k1_pubkey *label, unsigned char *label_tweak32, const unsigned char *recipient_scan_key, unsigned int m) {
    secp256k1_sha256 hash;
    unsigned char m_serialized[4];

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(label != NULL);
    ARG_CHECK(label_tweak32 != NULL);
    ARG_CHECK(recipient_scan_key != NULL);

    /* Compute label_tweak = hash(ser_256(b_scan) || ser_32(m))  [sha256 with tag "BIP0352/Label"] */
    secp256k1_silentpayments_sha256_init_label(&hash);
    secp256k1_sha256_write(&hash, recipient_scan_key, 32);
    secp256k1_write_be32(m_serialized, m);
    secp256k1_sha256_write(&hash, m_serialized, sizeof(m_serialized));
    secp256k1_sha256_finalize(&hash, label_tweak32);

    /* Compute label = label_tweak * G */
    if (!secp256k1_ec_pubkey_create(ctx, label, label_tweak32)) {
        return 0;
    }

    return 1;
}

int secp256k1_silentpayments_recipient_create_labelled_spend_pubkey(const secp256k1_context *ctx, secp256k1_pubkey *labelled_spend_pubkey, const secp256k1_pubkey *recipient_spend_pubkey, const secp256k1_pubkey *label) {
    secp256k1_ge B_m, label_addend;
    secp256k1_gej result_gej;
    secp256k1_ge result_ge;

    /* Sanity check inputs. */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(labelled_spend_pubkey != NULL);
    ARG_CHECK(recipient_spend_pubkey != NULL);
    ARG_CHECK(label != NULL);

    /* Calculate B_m = B_spend + label */
    secp256k1_pubkey_load(ctx, &B_m, recipient_spend_pubkey);
    secp256k1_pubkey_load(ctx, &label_addend, label);
    secp256k1_gej_set_ge(&result_gej, &B_m);
    secp256k1_gej_add_ge_var(&result_gej, &result_gej, &label_addend, NULL);

    /* Serialize B_m */
    secp256k1_ge_set_gej(&result_ge, &result_gej);
    secp256k1_pubkey_save(labelled_spend_pubkey, &result_ge);

    return 1;
}

int secp256k1_silentpayments_recipient_public_data_create(
    const secp256k1_context *ctx,
    secp256k1_silentpayments_public_data *public_data,
    const unsigned char *outpoint_smallest36,
    const secp256k1_xonly_pubkey * const *xonly_pubkeys,
    size_t n_xonly_pubkeys,
    const secp256k1_pubkey * const *plain_pubkeys,
    size_t n_plain_pubkeys
) {
    size_t i;
    size_t pubkeylen = 65;
    secp256k1_pubkey A_sum;
    secp256k1_ge A_sum_ge, addend;
    secp256k1_gej A_sum_gej;
    unsigned char input_hash_local[32];

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(public_data != NULL);
    ARG_CHECK(plain_pubkeys == NULL || n_plain_pubkeys >= 1);
    ARG_CHECK(xonly_pubkeys == NULL || n_xonly_pubkeys >= 1);
    ARG_CHECK((plain_pubkeys != NULL) || (xonly_pubkeys != NULL));
    ARG_CHECK((n_plain_pubkeys + n_xonly_pubkeys) >= 1);
    ARG_CHECK(outpoint_smallest36 != NULL);
    memset(input_hash_local, 0, 32);

    /* Compute input public keys sum: A_sum = A_1 + A_2 + ... + A_n */
    secp256k1_gej_set_infinity(&A_sum_gej);
    for (i = 0; i < n_plain_pubkeys; i++) {
        if (!secp256k1_pubkey_load(ctx, &addend, plain_pubkeys[i])) {
            return 0;
        }
        secp256k1_gej_add_ge_var(&A_sum_gej, &A_sum_gej, &addend, NULL);
    }
    for (i = 0; i < n_xonly_pubkeys; i++) {
        if (!secp256k1_xonly_pubkey_load(ctx, &addend, xonly_pubkeys[i])) {
            return 0;
        }
        secp256k1_gej_add_ge_var(&A_sum_gej, &A_sum_gej, &addend, NULL);
    }
    /* If the caller passes in all valid public keys but the public keys
     * sum to 0 (the point at infinity), we can't do anything except tell
     * the caller to try again with a different set of input public keys,
     * e.g. skip the current transaction and move to the next */
    if (secp256k1_gej_is_infinity(&A_sum_gej)) {
        return 0;
    }
    secp256k1_ge_set_gej(&A_sum_ge, &A_sum_gej);

    /* Compute input_hash = hash(outpoint_L || A_sum) */
    secp256k1_silentpayments_calculate_input_hash(input_hash_local, outpoint_smallest36, &A_sum_ge);
    secp256k1_pubkey_save(&A_sum, &A_sum_ge);
    /* serialize the public_data struct */
    public_data->data[0] = 0;
    secp256k1_ec_pubkey_serialize(ctx, &public_data->data[1], &pubkeylen, &A_sum, SECP256K1_EC_UNCOMPRESSED);
    memcpy(&public_data->data[1 + pubkeylen], input_hash_local, 32);
    return 1;
}

static int secp256k1_silentpayments_recipient_public_data_load(const secp256k1_context *ctx, secp256k1_pubkey *pubkey, unsigned char *input_hash, const secp256k1_silentpayments_public_data *public_data) {
    int combined;
    size_t pubkeylen = 65;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(public_data != NULL);

    combined = (int)public_data->data[0];
    ARG_CHECK(combined == 0 || combined == 1);
    if (combined) {
        ARG_CHECK(combined == 1 && input_hash == NULL);
    } else {
        ARG_CHECK(combined == 0 && input_hash != NULL);
        memcpy(input_hash, &public_data->data[1 + pubkeylen], 32);
    }
    if (!secp256k1_ec_pubkey_parse(ctx, pubkey, &public_data->data[1], pubkeylen)) {
        return 0;
    }
    return 1;
}

int secp256k1_silentpayments_recipient_public_data_serialize(const secp256k1_context *ctx, unsigned char *output33, const secp256k1_silentpayments_public_data *public_data) {
    secp256k1_pubkey pubkey;
    unsigned char input_hash[32];
    size_t pubkeylen = 33;

    ARG_CHECK(public_data->data[0] == 0);
    if (!secp256k1_silentpayments_recipient_public_data_load(ctx, &pubkey, input_hash, public_data)) {
        return 0;
    }
    if (!secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, input_hash)) {
        return 0;
    }
    secp256k1_ec_pubkey_serialize(ctx, output33, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED);
    return 1;
}

int secp256k1_silentpayments_recipient_public_data_parse(const secp256k1_context *ctx, secp256k1_silentpayments_public_data *public_data, const unsigned char *input33) {
    size_t inputlen = 33;
    size_t pubkeylen = 65;
    secp256k1_pubkey pubkey;

    ARG_CHECK(public_data != NULL);
    ARG_CHECK(input33 != NULL);
    if (!secp256k1_ec_pubkey_parse(ctx, &pubkey, input33, inputlen)) {
        return 0;
    }
    public_data->data[0] = 1;
    secp256k1_ec_pubkey_serialize(ctx, &public_data->data[1], &pubkeylen, &pubkey, SECP256K1_EC_UNCOMPRESSED);
    memset(&public_data->data[1 + pubkeylen], 0, 32);
    return 1;
}

int secp256k1_silentpayments_recipient_scan_outputs(
    const secp256k1_context *ctx,
    secp256k1_silentpayments_found_output **found_outputs, size_t *n_found_outputs,
    const secp256k1_xonly_pubkey * const *tx_outputs, size_t n_tx_outputs,
    const unsigned char *recipient_scan_key,
    const secp256k1_silentpayments_public_data *public_data,
    const secp256k1_pubkey *recipient_spend_pubkey,
    const secp256k1_silentpayments_label_lookup label_lookup,
    const void *label_context
) {
    secp256k1_scalar t_k_scalar;
    secp256k1_ge label_ge, recipient_spend_pubkey_ge;
    secp256k1_pubkey A_sum;
    secp256k1_xonly_pubkey P_output_xonly;
    unsigned char shared_secret[33];
    unsigned char label_tweak32[32];
    const unsigned char *label_tweak = label_tweak32;
    size_t i, k, n_found, found_idx;
    int found, combined;

    /* Sanity check inputs */
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(found_outputs != NULL);
    ARG_CHECK(n_found_outputs != NULL);
    ARG_CHECK(tx_outputs != NULL);
    ARG_CHECK(n_tx_outputs >= 1);
    ARG_CHECK(recipient_scan_key != NULL);
    ARG_CHECK(public_data != NULL);
    combined = (int)public_data->data[0];
    {
        unsigned char input_hash[32];
        unsigned char *input_hash_ptr;
        if (combined) {
            input_hash_ptr = NULL;
        } else {
            memset(input_hash, 0, 32);
            input_hash_ptr = input_hash;
        }
        if (!secp256k1_silentpayments_recipient_public_data_load(ctx, &A_sum, input_hash_ptr, public_data)) {
            return 0;
        }
        secp256k1_pubkey_load(ctx, &recipient_spend_pubkey_ge, recipient_spend_pubkey);
        if (!secp256k1_silentpayments_create_shared_secret(ctx, shared_secret, recipient_scan_key, &A_sum, input_hash_ptr)) {
            return 0;
        }
    }

    found_idx = 0;
    n_found = 0;
    k = 0;
    while (1) {
        secp256k1_ge P_output_ge = recipient_spend_pubkey_ge;
        /* Calculate t_k = hash(shared_secret || ser_32(k)) */
        secp256k1_silentpayments_create_t_k(&t_k_scalar, shared_secret, k);

        /* Calculate P_output = B_spend + t_k * G */
        if (!secp256k1_eckey_pubkey_tweak_add(&P_output_ge, &t_k_scalar)) {
            return 0;
        }

        found = 0;
        secp256k1_xonly_pubkey_save(&P_output_xonly, &P_output_ge);
        for (i = 0; i < n_tx_outputs; i++) {
            if (secp256k1_xonly_pubkey_cmp(ctx, &P_output_xonly, tx_outputs[i]) == 0) {
                label_tweak = NULL;
                found = 1;
                found_idx = i;
                break;
            }

            /* If not found, proceed to check for labels (if the labels cache is present) */
            if (label_lookup != NULL) {
                secp256k1_pubkey label_pubkey;
                secp256k1_ge P_output_negated_ge, tx_output_ge;
                secp256k1_gej tx_output_gej, label_gej;

                secp256k1_xonly_pubkey_load(ctx, &tx_output_ge, tx_outputs[i]);
                secp256k1_gej_set_ge(&tx_output_gej, &tx_output_ge);
                secp256k1_ge_neg(&P_output_negated_ge, &P_output_ge);
                /* Negate the generated output and calculate first scan label candidate:
                 * label1 = tx_output - P_output */
                secp256k1_gej_add_ge_var(&label_gej, &tx_output_gej, &P_output_negated_ge, NULL);
                secp256k1_ge_set_gej(&label_ge, &label_gej);
                secp256k1_pubkey_save(&label_pubkey, &label_ge);
                label_tweak = label_lookup(&label_pubkey, label_context);
                if (label_tweak != NULL) {
                    found = 1;
                    found_idx = i;
                    break;
                }

                secp256k1_gej_neg(&label_gej, &tx_output_gej);
                /* If not found, negate the tx_output and calculate second scan label candidate:
                 * label2 = -tx_output - P_output */
                secp256k1_gej_add_ge_var(&label_gej, &label_gej, &P_output_negated_ge, NULL);
                secp256k1_ge_set_gej(&label_ge, &label_gej);
                secp256k1_pubkey_save(&label_pubkey, &label_ge);
                label_tweak = label_lookup(&label_pubkey, label_context);
                if (label_tweak != NULL) {
                    found = 1;
                    found_idx = i;
                    break;
                }
            }
        }
        if (found) {
            found_outputs[n_found]->output = *tx_outputs[found_idx];
            secp256k1_scalar_get_b32(found_outputs[n_found]->tweak, &t_k_scalar);
            if (label_lookup != NULL && label_tweak != NULL) {
                found_outputs[n_found]->found_with_label = 1;
                if (!secp256k1_ec_seckey_tweak_add(ctx, found_outputs[n_found]->tweak, label_tweak)) {
                    return 0;
                }
                secp256k1_pubkey_save(&found_outputs[n_found]->label, &label_ge);
            } else {
                found_outputs[n_found]->found_with_label = 0;
                /* TODO: instead of using the tx_output, set the label with a properly invalid pubkey */
                secp256k1_pubkey_save(&found_outputs[n_found]->label, &P_output_ge);
            }
            /* Set everything for the next round of scanning */
            label_tweak = label_tweak32;
            n_found++;
            k++;
        } else {
            break;
        }
    }
    *n_found_outputs = n_found;
    return 1;
}

int secp256k1_silentpayments_recipient_create_shared_secret(const secp256k1_context *ctx, unsigned char *shared_secret33, const unsigned char *recipient_scan_key, const secp256k1_silentpayments_public_data *public_data) {
    secp256k1_pubkey A_tweaked;
    /* Sanity check inputs */
    ARG_CHECK(shared_secret33 != NULL);
    ARG_CHECK(recipient_scan_key != NULL);
    ARG_CHECK(public_data != NULL);
    ARG_CHECK(public_data->data[0] == 1);
    if (!secp256k1_silentpayments_recipient_public_data_load(ctx, &A_tweaked, NULL, public_data)) {
        return 0;
    }
    return secp256k1_silentpayments_create_shared_secret(ctx, shared_secret33, recipient_scan_key, &A_tweaked, NULL);
}

int secp256k1_silentpayments_recipient_create_output_pubkey(const secp256k1_context *ctx, secp256k1_xonly_pubkey *P_output_xonly, const unsigned char *shared_secret33, const secp256k1_pubkey *recipient_spend_pubkey, unsigned int k)
{
    return secp256k1_silentpayments_create_output_pubkey(ctx, P_output_xonly, shared_secret33, recipient_spend_pubkey, k);
}


#endif
