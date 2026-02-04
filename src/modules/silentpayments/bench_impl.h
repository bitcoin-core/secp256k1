/***********************************************************************
 * Copyright (c) 2024 josibake                                         *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_BENCH_H
#define SECP256K1_MODULE_SILENTPAYMENTS_BENCH_H

#include "../../../include/secp256k1_silentpayments.h"

/* upper bound of maximum taproot outputs per block: floor(1_000_000/43)
 * (needed for constructing the "worst-case scanning attack", where a single
 *  tx fills up a full bock of taproot outputs that all go to the same scankey group) */
#define MAX_P2TR_OUTPUTS_PER_BLOCK 23255

#define SP_BENCH_MAX_INPUTS  1
#define SP_BENCH_MAX_OUTPUTS MAX_P2TR_OUTPUTS_PER_BLOCK
#define SP_BENCH_MAX_LABELS  1000

typedef struct {
    secp256k1_context *ctx;
    secp256k1_pubkey spend_pubkey;
    unsigned char scan_key[32];
    secp256k1_xonly_pubkey *tx_outputs;
    secp256k1_xonly_pubkey **tx_outputs_ptrs;
    unsigned char *tx_outputs_ser;
    const unsigned char **tx_outputs_ser_ptrs_orig; /* original order of pointers to txs to scan */
    const unsigned char **tx_outputs_ser_ptrs;
    secp256k1_xonly_pubkey tx_inputs[SP_BENCH_MAX_INPUTS];
    const secp256k1_xonly_pubkey *tx_inputs_ptrs[SP_BENCH_MAX_INPUTS];
    secp256k1_silentpayments_found_output *found_outputs;
    secp256k1_silentpayments_found_output **found_outputs_ptrs;
    secp256k1_silentpayments_label_entry label_entries[SP_BENCH_MAX_LABELS];
    const secp256k1_silentpayments_label_entry *label_entries_ptrs[SP_BENCH_MAX_LABELS];
    unsigned char scalar[32];
    unsigned char smallest_outpoint[36];
    int num_labels, num_outputs;
} bench_silentpayments_data;

static void bench_silentpayments_scan_setup(void* arg) {
    int i;
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    const unsigned char smallest_outpoint[36] = {
        0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91,
        0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75, 0x4c, 0xfe,
        0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40,
        0x96, 0xc5, 0x4f, 0x18, 0xf4, 0x00, 0x00, 0x00, 0x00,
    };
    const unsigned char spend_pubkey[33] = {
        0x02,0xee,0x97,0xdf,0x83,0xb2,0x54,0x6a,
        0xf5,0xa7,0xd0,0x62,0x15,0xd9,0x8b,0xcb,
        0x63,0x7f,0xe0,0x5d,0xd0,0xfa,0x37,0x3b,
        0xd8,0x20,0xe6,0x64,0xd3,0x72,0xde,0x9a,0x01
    };
    const unsigned char scan_key[32] = {
        0xa8,0x90,0x54,0xc9,0x5b,0xe3,0xc3,0x01,
        0x56,0x65,0x74,0xf2,0xaa,0x93,0xad,0xe0,
        0x51,0x85,0x09,0x03,0xa6,0x9c,0xbd,0xd1,
        0xd4,0x7e,0xae,0x26,0x3d,0x7b,0xc0,0x31
    };
    secp256k1_keypair input_keypair;
    size_t pubkeylen = 33;

    for (i = 0; i < 32; i++) {
        data->scalar[i] = i + 1;
    }
    /* Create the input public key for the full scan from the scalar.
     */
    CHECK(secp256k1_keypair_create(data->ctx, &input_keypair, data->scalar));
    CHECK(secp256k1_keypair_xonly_pub(data->ctx, &data->tx_inputs[0], NULL, &input_keypair));
    data->tx_inputs_ptrs[0] = &data->tx_inputs[0];
    CHECK(secp256k1_ec_pubkey_parse(data->ctx, &data->spend_pubkey, spend_pubkey, pubkeylen));
    memcpy(data->scan_key, scan_key, 32);
    memcpy(data->smallest_outpoint, smallest_outpoint, 36);

    /* prepare transaction outputs for the "worst-case scanning attack",
     * can be used for typical scanning scenarios as well */
    {
        secp256k1_silentpayments_recipient *recipients = malloc(sizeof(secp256k1_silentpayments_recipient) * SP_BENCH_MAX_OUTPUTS);
        const secp256k1_silentpayments_recipient **recipients_ptrs = malloc(sizeof(secp256k1_silentpayments_recipient*) * SP_BENCH_MAX_OUTPUTS);
        const secp256k1_keypair *taproot_keypairs_ptrs[SP_BENCH_MAX_INPUTS];
        secp256k1_pubkey scan_pubkey;
        secp256k1_pubkey labeled_spend_pubkey;

        CHECK(secp256k1_ec_pubkey_create(data->ctx, &scan_pubkey, data->scan_key));
        for (i = 0; i < SP_BENCH_MAX_LABELS; i++) {
            CHECK(secp256k1_silentpayments_recipient_label_create(data->ctx,
                &data->label_entries[i].label, data->label_entries[i].label_tweak,
                data->scan_key, i));
            data->label_entries_ptrs[i] = &data->label_entries[i];
        }
        CHECK(secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(data->ctx,
            &labeled_spend_pubkey, &data->spend_pubkey, &data->label_entries[0].label));

        data->tx_outputs = malloc(sizeof(secp256k1_xonly_pubkey) * SP_BENCH_MAX_OUTPUTS);
        data->tx_outputs_ptrs = malloc(sizeof(secp256k1_xonly_pubkey*) * SP_BENCH_MAX_OUTPUTS);
        data->tx_outputs_ser = malloc(32 * SP_BENCH_MAX_OUTPUTS);
        data->tx_outputs_ser_ptrs_orig = malloc(sizeof(unsigned char*) * SP_BENCH_MAX_OUTPUTS);
        data->tx_outputs_ser_ptrs = malloc(sizeof(unsigned char*) * SP_BENCH_MAX_OUTPUTS);
        data->found_outputs = malloc(sizeof(secp256k1_silentpayments_found_output) * SP_BENCH_MAX_OUTPUTS);
        data->found_outputs_ptrs = malloc(sizeof(secp256k1_silentpayments_found_output*) * SP_BENCH_MAX_OUTPUTS);

        taproot_keypairs_ptrs[0] = &input_keypair;
        for (i = 0; i < SP_BENCH_MAX_OUTPUTS; i++) {
            data->tx_outputs_ptrs[i] = &data->tx_outputs[i];
            recipients_ptrs[i] = &recipients[i];
            recipients[i].scan_pubkey = scan_pubkey;
            recipients[i].spend_pubkey = labeled_spend_pubkey;
            recipients[i].index = i;
        }
        CHECK(secp256k1_silentpayments_sender_create_outputs(data->ctx, data->tx_outputs_ptrs, recipients_ptrs,
            SP_BENCH_MAX_OUTPUTS, data->smallest_outpoint, taproot_keypairs_ptrs, SP_BENCH_MAX_INPUTS, NULL, 0));

        for (i = 0; i < SP_BENCH_MAX_OUTPUTS; i++) {
            CHECK(secp256k1_xonly_pubkey_serialize(data->ctx, &data->tx_outputs_ser[32*i], &data->tx_outputs[i]));
            data->tx_outputs_ser_ptrs_orig[i] = &data->tx_outputs_ser[32*i];
            data->found_outputs_ptrs[i] = &data->found_outputs[i];
        }

        free(recipients_ptrs);
        free(recipients);
    }
}

static void bench_silentpayments_scan_teardown(void* arg, int iters) {
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    (void)iters;

    free(data->tx_outputs);
    free(data->tx_outputs_ptrs);
    free(data->tx_outputs_ser);
    free(data->tx_outputs_ser_ptrs_orig);
    free(data->tx_outputs_ser_ptrs);
    free(data->found_outputs);
    free(data->found_outputs_ptrs);
}

static void bench_silentpayments_scan(void* arg, int iters, int has_matches) {
    bench_silentpayments_data *data = (bench_silentpayments_data*)arg;
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    uint32_t n_found = 0;
    int i, j;

    if (has_matches) {
        CHECK(data->num_labels >= 1);
    }
    CHECK(data->num_labels <= SP_BENCH_MAX_LABELS);
    CHECK(data->num_outputs <= SP_BENCH_MAX_OUTPUTS);

    if (has_matches) {
        /* to exhibit the worst-case, move label that would match (m=0) to the end of the label list */
        secp256k1_silentpayments_label_entry match_label = data->label_entries[0];
        data->label_entries[0] = data->label_entries[data->num_labels - 1];
        data->label_entries[data->num_labels - 1] = match_label;
    } else {
        /* modify scan key to avoid matches */
        data->scan_key[31] ^= 0x01;
    }

    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(data->ctx,
            &prevouts_summary, data->smallest_outpoint, data->tx_inputs_ptrs, SP_BENCH_MAX_INPUTS, NULL, 0
        ));
        /* restore original order of txs to scan (the scan function sorts them in place) */
        for (j = 0; j < data->num_outputs; j++) {
            data->tx_outputs_ser_ptrs[j] = data->tx_outputs_ser_ptrs_orig[j];
        }
        CHECK(secp256k1_silentpayments_recipient_scan_outputs(data->ctx,
            data->found_outputs_ptrs, &n_found,
            data->tx_outputs_ser_ptrs, data->num_outputs,
            data->scan_key, &prevouts_summary, &data->spend_pubkey,
            data->num_labels > 0 ? data->label_entries_ptrs : NULL, data->num_labels)
        );
        CHECK(n_found == (uint32_t)(has_matches ? data->num_outputs : 0));
    }
}

static void bench_silentpayments_scan_nomatch(void *arg, int iters) {
    bench_silentpayments_scan(arg, iters, 0);
}

static void bench_silentpayments_scan_match(void *arg, int iters) {
    bench_silentpayments_scan(arg, iters, 1);
}

static void run_silentpayments_bench(int iters, int argc, char** argv) {
    const int num_labels_bench[] = {0, 1, 2, 5, 10, 20, 50, 100};
    const int num_outputs_bench[] = {10, 100, MAX_P2TR_OUTPUTS_PER_BLOCK/10};
    bench_silentpayments_data data;
    int d = argc == 1;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    if (d || have_flag(argc, argv, "silentpayments") || have_flag(argc, argv, "silentpayments_scan_nomatch")) {
        size_t l, o;
        for (o = 0; o < sizeof(num_outputs_bench)/sizeof(num_outputs_bench[0]); o++) {
            for (l = 0; l < sizeof(num_labels_bench)/sizeof(num_labels_bench[0]); l++) {
                const int num_labels = num_labels_bench[l];
                const int num_outputs = num_outputs_bench[o];
                char str[64];
                data.num_labels = num_labels;
                data.num_outputs = num_outputs;
                sprintf(str, "silentpayments_scan_nomatch_N=%i_L=%i", num_outputs, num_labels);
                run_benchmark(str, bench_silentpayments_scan_nomatch, bench_silentpayments_scan_setup, bench_silentpayments_scan_teardown, &data, 10, iters);
            }
            printf("\n");
        }
    }

    if (d || have_flag(argc, argv, "silentpayments") || have_flag(argc, argv, "silentpayments_scan_worstcase")) {
        const int num_labels_bench_wc[] = {1, 2, 5, 10, 20, 50, 100, 200, 500};
        size_t l;
        for (l = 0; l < sizeof(num_labels_bench_wc)/sizeof(num_labels_bench_wc[0]); l++) {
            const int num_labels = num_labels_bench_wc[l];
            char str[64];
            data.num_labels = num_labels;
            data.num_outputs = MAX_P2TR_OUTPUTS_PER_BLOCK;
            sprintf(str, "silentpayments_scan_worstcase_L=%i", num_labels);
            run_benchmark(str, bench_silentpayments_scan_match, bench_silentpayments_scan_setup, bench_silentpayments_scan_teardown, &data, 1, 10);
        }
        printf("\n");
    }

    secp256k1_context_destroy(data.ctx);
}

#endif /* SECP256K1_MODULE_SILENTPAYMENTS_BENCH_H */
