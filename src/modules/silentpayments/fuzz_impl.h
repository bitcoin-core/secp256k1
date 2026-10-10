/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_FUZZ_H
#define SECP256K1_MODULE_SILENTPAYMENTS_FUZZ_H

#include "../../../include/secp256k1_silentpayments.h"

/* One sender input pays one recipient. The recipient scans the sent output
 * among decoys: its own spend key and up to two x-only keys from the fuzz
 * input. It must find the sent output and can spend every output it finds. */
static void fuzz_silentpayments(fuzz_data_provider *provider) {
    secp256k1_silentpayments_recipient recipient;
    const secp256k1_silentpayments_recipient *recipient_ptr[1];
    secp256k1_xonly_pubkey output, outputs[4];
    secp256k1_xonly_pubkey *output_ptr[1];
    const secp256k1_xonly_pubkey *tx_outputs[4];
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    secp256k1_silentpayments_found_output found[4];
    secp256k1_silentpayments_found_output *found_ptr[4];
    secp256k1_pubkey input_pubkey;
    const secp256k1_pubkey *input_pubkey_ptr[1];
    unsigned char spend_seckey[32], negated_from[32];
    const unsigned char *input_seckey, *scan_seckey, *spend_seckey_in, *outpoint36, *extra32;
    size_t n_tx_outputs, i;
    uint32_t n_found;
    int negated = 0, sent = -1;

    input_seckey = fuzz_consume_seckey(provider);
    scan_seckey = fuzz_consume_seckey(provider);
    spend_seckey_in = fuzz_consume_seckey(provider);
    outpoint36 = fuzz_consume_bytes(provider, 36);
    if (!input_seckey || !scan_seckey || !spend_seckey_in || !outpoint36) {
        return;
    }
    memcpy(spend_seckey, spend_seckey_in, sizeof(spend_seckey));

    /* Sender */
    CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &recipient.scan_pubkey, scan_seckey) == 1);
    CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &recipient.spend_pubkey, spend_seckey) == 1);
    recipient.index = 0;
    recipient_ptr[0] = &recipient;
    output_ptr[0] = &output;
    if (!fuzz_check_bool(secp256k1_silentpayments_sender_create_outputs(fuzz_ctx, output_ptr, recipient_ptr, 1, outpoint36, NULL, 0, &input_seckey, 1))) {
        /* With one valid input key, this fails only for the spend key -t, where t is
         * the output tweak. Then the spend key t must work; the scan below gives t. */
        memcpy(negated_from, spend_seckey, sizeof(negated_from));
        negated = 1;
        CHECK(secp256k1_ec_seckey_negate(fuzz_ctx, spend_seckey) == 1);
        CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &recipient.spend_pubkey, spend_seckey) == 1);
        CHECK(secp256k1_silentpayments_sender_create_outputs(fuzz_ctx, output_ptr, recipient_ptr, 1, outpoint36, NULL, 0, &input_seckey, 1) == 1);
    }

    /* Recipient: the same inputs as the sender's, so the summary succeeds too */
    CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &input_pubkey, input_seckey) == 1);
    input_pubkey_ptr[0] = &input_pubkey;
    CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(fuzz_ctx, &prevouts_summary, outpoint36, NULL, 0, input_pubkey_ptr, 1) == 1);
    CHECK(secp256k1_xonly_pubkey_from_pubkey(fuzz_ctx, &outputs[0], NULL, &recipient.spend_pubkey) == 1);
    outputs[1] = output;
    n_tx_outputs = 2;
    while (n_tx_outputs < 4 && (extra32 = fuzz_consume_bytes(provider, 32)) != NULL) {
        if (fuzz_check_bool(secp256k1_xonly_pubkey_parse(fuzz_ctx, &outputs[n_tx_outputs], extra32))) {
            n_tx_outputs++;
        }
    }
    for (i = 0; i < 4; i++) {
        tx_outputs[i] = &outputs[i];
        found_ptr[i] = &found[i];
    }
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(fuzz_ctx, found_ptr, &n_found, tx_outputs, n_tx_outputs, scan_seckey, &prevouts_summary, &recipient.spend_pubkey, NULL, NULL) == 1);

    /* Every found output is spendable with the spend key plus its tweak, and the sent one is found */
    for (i = 0; i < n_found; i++) {
        unsigned char key[32];
        secp256k1_keypair keypair;
        secp256k1_xonly_pubkey spend_output;
        CHECK(found[i].found_with_label == 0);
        memcpy(key, spend_seckey, sizeof(key));
        CHECK(secp256k1_ec_seckey_tweak_add(fuzz_ctx, key, found[i].tweak) == 1);
        CHECK(secp256k1_keypair_create(fuzz_ctx, &keypair, key) == 1);
        CHECK(secp256k1_keypair_xonly_pub(fuzz_ctx, &spend_output, NULL, &keypair) == 1);
        CHECK(secp256k1_xonly_pubkey_cmp(fuzz_ctx, &spend_output, &found[i].output) == 0);
        if (secp256k1_xonly_pubkey_cmp(fuzz_ctx, &found[i].output, &output) == 0) {
            sent = (int)i;
        }
    }
    CHECK(sent >= 0);
    if (negated) {
        /* The first spend key was -t */
        CHECK(secp256k1_ec_seckey_tweak_add(fuzz_ctx, negated_from, found[sent].tweak) == 0);
    }
}

#endif /* SECP256K1_MODULE_SILENTPAYMENTS_FUZZ_H */
