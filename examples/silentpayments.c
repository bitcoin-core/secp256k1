/*************************************************************************
 * Written in 2024 by josibake                                           *
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_extrakeys.h>
#include <secp256k1_silentpayments.h>

#include "examples_util.h"

/* Static data for Bob and Carol's silent payment addresses.
 * This consists of a scan key for each and the addresse data for each
 */
static unsigned char smallest_outpoint[36] = {
    0x16,0x9e,0x1e,0x83,0xe9,0x30,0x85,0x33,0x91,
    0xbc,0x6f,0x35,0xf6,0x05,0xc6,0x75,0x4c,0xfe,
    0xad,0x57,0xcf,0x83,0x87,0x63,0x9d,0x3b,0x40,
    0x96,0xc5,0x4f,0x18,0xf4,0x00,0x00,0x00,0x00
};
static unsigned char bob_scan_key[32] = {
    0xa8,0x90,0x54,0xc9,0x5b,0xe3,0xc3,0x01,
    0x56,0x65,0x74,0xf2,0xaa,0x93,0xad,0xe0,
    0x51,0x85,0x09,0x03,0xa6,0x9c,0xbd,0xd1,
    0xd4,0x7e,0xae,0x26,0x3d,0x7b,0xc0,0x31
};
static unsigned char bob_spend_pubkey[33] = {
    0x02,0xee,0x97,0xdf,0x83,0xb2,0x54,0x6a,
    0xf5,0xa7,0xd0,0x62,0x15,0xd9,0x8b,0xcb,
    0x63,0x7f,0xe0,0x5d,0xd0,0xfa,0x37,0x3b,
    0xd8,0x20,0xe6,0x64,0xd3,0x72,0xde,0x9a,0x01
};
static unsigned char bob_address[2][33] = {
    {
        0x02,0x15,0x40,0xae,0xa8,0x97,0x54,0x7a,
        0xd4,0x39,0xb4,0xe0,0xf6,0x09,0xe5,0xf0,
        0xfa,0x63,0xde,0x89,0xab,0x11,0xed,0xe3,
        0x1e,0x8c,0xde,0x4b,0xe2,0x19,0x42,0x5f,0x23
    },
    {
        0x02,0x3e,0xff,0xf8,0x18,0x51,0x65,0xea,
        0x63,0xa9,0x92,0xb3,0x9f,0x31,0xd8,0xfd,
        0x8e,0x0e,0x64,0xae,0xf9,0xd3,0x88,0x07,
        0x34,0x97,0x37,0x14,0xa5,0x3d,0x83,0x11,0x8d
    }
};
static unsigned char carol_scan_key[32] = {
    0x04,0xb2,0xa4,0x11,0x63,0x5c,0x09,0x77,
    0x59,0xaa,0xcd,0x0f,0x00,0x5a,0x4c,0x82,
    0xc8,0xc9,0x28,0x62,0xc6,0xfc,0x28,0x4b,
    0x80,0xb8,0xef,0xeb,0xc2,0x0c,0x3d,0x17
};
static unsigned char carol_address[2][33] = {
    {
        0x03,0xbb,0xc6,0x3f,0x12,0x74,0x5d,0x3b,
        0x9e,0x9d,0x24,0xc6,0xcd,0x7a,0x1e,0xfe,
        0xba,0xd0,0xa7,0xf4,0x69,0x23,0x2f,0xbe,
        0xcf,0x31,0xfb,0xa7,0xb4,0xf7,0xdd,0xed,0xa8
    },
    {
        0x03,0x81,0xeb,0x9a,0x9a,0x9e,0xc7,0x39,
        0xd5,0x27,0xc1,0x63,0x1b,0x31,0xb4,0x21,
        0x56,0x6f,0x5c,0x2a,0x47,0xb4,0xab,0x5b,
        0x1f,0x6a,0x68,0x6d,0xfb,0x68,0xea,0xb7,0x16
    }
};

/* Labels
 * The structs and call back function are for demonstration only and not optimized.
 * In a production usecase, it is expected that the caller will be using a much more performant
 * method for storing and querying labels.
 */

struct label_cache_entry {
    secp256k1_pubkey label;
    unsigned char label_tweak[32];
};

struct labels_cache {
    const secp256k1_context *ctx;
    size_t entries_used;
    struct label_cache_entry entries[5];
};

const unsigned char* label_lookup(const secp256k1_pubkey* key, const void* cache_ptr) {
    const struct labels_cache* cache = (const struct labels_cache*)cache_ptr;
    size_t i;
    for (i = 0; i < cache->entries_used; i++) {
        if (secp256k1_ec_pubkey_cmp(cache->ctx, &cache->entries[i].label, key) == 0) {
            return cache->entries[i].label_tweak;
        }
    }
    return NULL;
}

int main(void) {
    enum { N_TX_INPUTS = 2, N_TX_OUTPUTS = 3 };
    unsigned char randomize[32];
    unsigned char xonly_print[32];
    secp256k1_xonly_pubkey tx_inputs[N_TX_INPUTS];
    secp256k1_xonly_pubkey tx_outputs[N_TX_OUTPUTS];
    int ret;
    size_t i;
    /* Before we can call actual API functions, we need to create a "context". */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail. */
    ret = secp256k1_context_randomize(ctx, randomize);
    assert(ret);

    /*** Sending ***/
    {
        secp256k1_keypair sender_seckeys[N_TX_INPUTS];
        const secp256k1_keypair *sender_seckey_ptrs[N_TX_INPUTS];
        secp256k1_silentpayments_recipient recipients[N_TX_OUTPUTS];
        const secp256k1_silentpayments_recipient *recipient_ptrs[N_TX_OUTPUTS];
        secp256k1_xonly_pubkey *generated_output_ptrs[N_TX_OUTPUTS];
        char* address_amounts[N_TX_OUTPUTS] = {"1.0 BTC", "2.0 BTC", "3.0 BTC"};
        unsigned char (*sp_addresses[N_TX_OUTPUTS])[2][33];

        /*** Generate private keys for the sender ***
         *
         * In this example, only taproot inputs are used but the function can be called with
         * a mix of taproot seckeys and plain seckeys. Taproot seckeys are passed as keypairs
         * to allow the sending function to check if the private keys need to be negated without needing
         * to do an expensive pubkey generation. This is not needed for plain seckeys since there is no need
         * for negation.
         *
         * The public key from each input keypair is saved in the `tx_inputs` array. This array will be used
         * later in the example to represent the public keys the recipient will extracte from the
         * transaction inputs.
         */

        for (i = 0; i < 2; i++) {
            /* If the secret key is zero or out of range (bigger than secp256k1's
             * order), we try to sample a new key. Note that the probability of this
             * happening is negligible. */
            while (1) {
                unsigned char seckey[32];
                if (!fill_random(seckey, sizeof(seckey))) {
                    printf("Failed to generate randomness\n");
                    return 1;
                }
                /* Try to create a keypair with a valid context, it should only fail if
                 * the secret key is zero or out of range. */
                if (secp256k1_keypair_create(ctx, &sender_seckeys[i], seckey)) {
                    sender_seckey_ptrs[i] = &sender_seckeys[i];
                    ret = secp256k1_keypair_xonly_pub(ctx, &tx_inputs[i], NULL, &sender_seckeys[i]);
                    assert(ret);
                    break;
                } else {
                    printf("Failed to create keypair\n");
                    return 1;
                }
            }
        }
        /*** Create the recipient objects ***/

        /* Alice is sending to Bob and Carol in this transaction:
         *
         *     1. One output to Bob's labelled address
         *     2. Two outputs for Carol (1.0 and 3.0 bitcoin)
         *
         * Alice creates the recipient objects and adds the index of the original ordering (i.e. the ordering
         * of the `sp_addresses` array) to each object. This index is used to return the generated outputs in
         * the original ordering so that Alice can match up the generated outputs with the correct amounts.
         *
         * Note: to create multiple outputs for Carol, Alice simply passes her silent payment
         * address mutltiple times.
         */
        sp_addresses[0] = &carol_address; /* : 1.0 BTC */
        sp_addresses[1] = &bob_address;   /* : 2.0 BTC */
        sp_addresses[2] = &carol_address; /* : 3.0 BTC */
        for (i = 0; i < N_TX_OUTPUTS; i++) {
            ret = secp256k1_ec_pubkey_parse(ctx, &recipients[i].scan_pubkey, (*(sp_addresses[i]))[0], 33);
            assert(ret);
            ret = secp256k1_ec_pubkey_parse(ctx, &recipients[i].spend_pubkey, (*(sp_addresses[i]))[1], 33);
            assert(ret);
            recipients[i].index = i;
            recipient_ptrs[i] = &recipients[i];
        }
        for (i = 0; i < N_TX_OUTPUTS; i++) {
            generated_output_ptrs[i] = &tx_outputs[i];
        }
        ret = secp256k1_silentpayments_sender_create_outputs(ctx,
            generated_output_ptrs,
            recipient_ptrs, N_TX_OUTPUTS,
            smallest_outpoint,
            sender_seckey_ptrs, N_TX_INPUTS,
            NULL, 0
        );
        assert(ret);
        printf("Alice created the following outputs for Bob and Carol: \n");
        for (i = 0; i < N_TX_OUTPUTS; i++) {
            printf("    ");
            printf("%s : ", address_amounts[i]);
            secp256k1_xonly_pubkey_serialize(ctx, xonly_print, &tx_outputs[i]);
            print_hex(xonly_print, sizeof(xonly_print));
        }
        /* It's best practice to try to clear secrets from memory after using them.
         * This is done because some bugs can allow an attacker to leak memory, for
         * example through "out of bounds" array access (see Heartbleed), Or the OS
         * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
         *
         * Here we are preventing these writes from being optimized out, as any good compiler
         * will remove any writes that aren't used. */
        for (i = 0; i < N_TX_INPUTS; i++) {
            secure_erase(&sender_seckeys[i], sizeof(sender_seckeys[i]));
        }
    }

    /*** Receiving ***/
    {
        /*** Transaction data ***
         *
         * Here we create a few global variables to represent the transaction data:
         *
         *     1. The transaction inputs, `tx_input_ptrs`
         *     2. The transaction outputs, `tx_output_ptrs`
         *
         * These will be used to demonstrate scanning as a full node and scanning as a light client.
         */
        const secp256k1_xonly_pubkey *tx_input_ptrs[N_TX_INPUTS];
        const secp256k1_xonly_pubkey *tx_output_ptrs[N_TX_OUTPUTS];
        unsigned char light_client_data33[33];

        for (i = 0; i < N_TX_INPUTS; i++) {
            tx_input_ptrs[i] = &tx_inputs[i];
        }
        for (i = 0; i < N_TX_OUTPUTS; i++) {
            tx_output_ptrs[i] = &tx_outputs[i];
        }

        /*** Scanning with labels as a full node (Bob) ***
         *
         * Since Bob has access to the full transaction, scanning is simple:
         *
         *     1. Collect the relevant data from the transaction inputs and call
         *        `secp256k1_silentpayments_recipient_public_data_create`
         *     2. Call `secp256k1_silentpayments_recipient_scan_outputs`
         *
         * Additionally, since Bob has access to the full transaction outputs when scanning its easy for him
         * to scan with labels, as demonstrated below. For efficient scanning, Bob keeps a cache of
         * every label he has previously used and uses a callback to check if a potential label exists
         * in his cache. Since the labels are created using an incremental integer `m`, if Bob ever
         * forgets how many labels he has previously used, he can pregenerate a large number of
         * labels (e.g. 0..100_000) and use that while scanning.
         */
        {
            secp256k1_silentpayments_found_output found_outputs[N_TX_OUTPUTS];
            secp256k1_silentpayments_found_output *found_output_ptrs[N_TX_OUTPUTS];
            secp256k1_silentpayments_public_data public_data;
            secp256k1_pubkey spend_pubkey;
            size_t n_found_outputs;
            unsigned int m = 1;
            struct labels_cache labels_cache;

            for (i = 0; i < N_TX_OUTPUTS; i++) {
                found_output_ptrs[i] = &found_outputs[i];
            }

            /* In this contrived example, our label context needs the secp256k1 context because our lookup function
             * is calling `secp256k1_ec_pubkey_cmp`. In practice, this context can be anything the lookup function needs.
             */
            labels_cache.ctx = ctx;

            /* Load Bob's spend public key */
            ret = secp256k1_ec_pubkey_parse(ctx, &spend_pubkey, bob_spend_pubkey, 33);

            /* Add an entry to the cache. This implies Bob has previously called `secp256k1_silentpayments_recipient_create_labelled_spend_pubkey`
             * and used the labelled spend pubkey to encode a labelled silent payments address.
             */
            ret = secp256k1_silentpayments_recipient_create_label_tweak(ctx,
                &labels_cache.entries[0].label,
                labels_cache.entries[0].label_tweak,
                bob_scan_key,
                m
            );
            assert(ret);
            labels_cache.entries_used = 1;

            /* Bob collects the data from the transaction inputs and creates a `secp256k1_silentpayments_public_data` object.
             * He uses this for his own scanning and also serializes the `public_data` object to send to light clients. We will
             * use this later for Carol, who is scanning as a light client. Note, anyone can create and vend these `public_data`
             * objecs, i.e. you don't need to be a silent payments wallet, just someone interested in vending this data to light
             * clients, e.g. a wallet service provider. In our example, Bob is scanning for himself but also sharing this data
             * with light clients.
             */
            ret = secp256k1_silentpayments_recipient_public_data_create(ctx,
                &public_data,
                smallest_outpoint,
                tx_input_ptrs, N_TX_INPUTS,
                NULL, 0 /* null because no eligible plain pubkey inputs were found in the tx */
            );
            assert(ret);
            /* Save the `public_data` output. This combines the `input_hash` scalar and public key sum by multiplying `input_hash * A_sum`.
             * The output is then saved as a 33 byte compressed key. Storing it this way saves 32 bytes for the light client because
             * now it can be send as a 33 byte compressed public key instead of 33 bytes for A_sum and 32 bytes for input_hash.
             */
            ret = secp256k1_silentpayments_recipient_public_data_serialize(ctx, light_client_data33, &public_data);
            assert(ret);

            /* Scan the transaction */
            n_found_outputs = 0;
            ret = secp256k1_silentpayments_recipient_scan_outputs(ctx,
                found_output_ptrs, &n_found_outputs,
                tx_output_ptrs, N_TX_OUTPUTS,
                bob_scan_key,
                &public_data,
                &spend_pubkey,
                label_lookup, &labels_cache /* NULL, NULL if scanning without labels */
            );
            assert(n_found_outputs == 1);
            printf("\n");
            printf("Bob found the following outputs: \n");
            for (i = 0; i < n_found_outputs; i++) {
                printf("    ");
                secp256k1_xonly_pubkey_serialize(ctx, xonly_print, &found_outputs[i].output);
                print_hex(xonly_print, sizeof(xonly_print));
            }
        }

        /*** Scanning as a light client (Carol) ***
         *
         * Being a light client, Carol likely does not have access to the transaction outputs. This
         * means she will need to first generate an output, check if it exists in the UTXO set (e.g.
         * BIP158 or some other means of querying) and only proceed to check the next output (by
         * incrementing `k`) if the first output exists.
         *
         * For the transaction inputs, she needs the 33 byte compressed public key which is `input_hash * A_sum`.
         */
        {
            /* In practice, Carol wouldn't know the number of outputs ahead of time but we are cheating here
             * to keep the example simple.
             */
            unsigned char ser_found_outputs[2][32];
            unsigned char shared_secret[33];
            secp256k1_pubkey spend_pubkey;
            secp256k1_silentpayments_public_data public_data;
            size_t n_found_outputs;

            /* Load Carol's spend public key */
            ret = secp256k1_ec_pubkey_parse(ctx, &spend_pubkey, carol_address[1], 33);
            assert(ret);

            /* Scan, one output at a time, using the light client data from earlier */
            ret = secp256k1_silentpayments_recipient_public_data_parse(ctx, &public_data, light_client_data33);
            assert(ret);
            ret = secp256k1_silentpayments_recipient_create_shared_secret(ctx,
                shared_secret,
                carol_scan_key,
                &public_data
            );
            assert(ret);
            n_found_outputs = 0;
            {
                int found = 0;
                size_t k = 0;
                secp256k1_xonly_pubkey potential_output;

                while(1) {

                    ret = secp256k1_silentpayments_recipient_create_output_pubkey(ctx,
                        &potential_output,
                        shared_secret,
                        &spend_pubkey,
                        k
                    );
                    assert(ret);
                    /* At this point, we check that the utxo exists with a light client protocol.
                     * For this example, we'll just iterate through the list of transaction outputs
                     */
                    found = 0;
                    for (i = 0; i < N_TX_OUTPUTS; i++) {
                        if (secp256k1_xonly_pubkey_cmp(ctx, &potential_output, &tx_outputs[i]) == 0) {
                            secp256k1_xonly_pubkey_serialize(ctx, ser_found_outputs[n_found_outputs], &potential_output);
                            /* If found, create a new output with k++ and check again */
                            found = 1;
                            n_found_outputs++;
                            k++;
                            break;
                        }
                    }
                    /* If we generate an output and it does not exist in the UTXO set,
                     * we are done scanning this transaction */
                    if (!found) {
                        break;
                    }
                }
            }

            printf("\n");
            printf("Carol found the following outputs: \n");
            for (i = 0; i < n_found_outputs; i++) {
                printf("    ");
                print_hex(ser_found_outputs[i], 32);
            }
        }
    }

    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);
    return 0;
}
