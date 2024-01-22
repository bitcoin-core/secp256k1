/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SILENTPAYMENTS_TESTS_H
#define SECP256K1_MODULE_SILENTPAYMENTS_TESTS_H

#include "../../../include/secp256k1_silentpayments.h"
#include "../../unit_test.h"

/** Constants
 *
 *   Malformed Seckey: a seckey that is all zeros
 *          Addresses: scan and spend public keys for Bob and Carol
 *            Outputs: generated outputs from Alice's secret key and Bob/Carol's
 *                     scan public keys
 *  Smallest Outpoint: smallest outpoint lexicographically from the transaction
 *             Seckey: secret key for Alice
 *
 *  The values themselves are not important.
 */
static unsigned char MALFORMED_SECKEY[32] = { 0x00 };
static unsigned char BOB_ADDRESS[2][33] = {
    {
        0x02, 0x15, 0x40, 0xae, 0xa8, 0x97, 0x54, 0x7a,
        0xd4, 0x39, 0xb4, 0xe0, 0xf6, 0x09, 0xe5, 0xf0,
        0xfa, 0x63, 0xde, 0x89, 0xab, 0x11, 0xed, 0xe3,
        0x1e, 0x8c, 0xde, 0x4b, 0xe2, 0x19, 0x42, 0x5f,
        0x23
    },
    {
        0x02, 0x3e, 0xff, 0xf8, 0x18, 0x51, 0x65, 0xea,
        0x63, 0xa9, 0x92, 0xb3, 0x9f, 0x31, 0xd8, 0xfd,
        0x8e, 0x0e, 0x64, 0xae, 0xf9, 0xd3, 0x88, 0x07,
        0x34, 0x97, 0x37, 0x14, 0xa5, 0x3d, 0x83, 0x11,
        0x8d
    }
};
static unsigned char CAROL_ADDRESS[2][33] = {
    {
        0x03, 0xbb, 0xc6, 0x3f, 0x12, 0x74, 0x5d, 0x3b,
        0x9e, 0x9d, 0x24, 0xc6, 0xcd, 0x7a, 0x1e, 0xfe,
        0xba, 0xd0, 0xa7, 0xf4, 0x69, 0x23, 0x2f, 0xbe,
        0xcf, 0x31, 0xfb, 0xa7, 0xb4, 0xf7, 0xdd, 0xed,
        0xa8
    },
    {
        0x03, 0x81, 0xeb, 0x9a, 0x9a, 0x9e, 0xc7, 0x39,
        0xd5, 0x27, 0xc1, 0x63, 0x1b, 0x31, 0xb4, 0x21,
        0x56, 0x6f, 0x5c, 0x2a, 0x47, 0xb4, 0xab, 0x5b,
        0x1f, 0x6a, 0x68, 0x6d, 0xfb, 0x68, 0xea, 0xb7,
        0x16
    }
};
static unsigned char BOB_OUTPUT[32] = {
    0x46, 0x0d, 0x68, 0x08, 0x65, 0x64, 0x45, 0xee,
    0x4d, 0x4e, 0xc0, 0x8e, 0xba, 0x8a, 0x66, 0xea,
    0x66, 0x8e, 0x4e, 0x12, 0x98, 0x9a, 0x0e, 0x60,
    0x4b, 0x5c, 0x36, 0x0e, 0x43, 0xf5, 0x5a, 0xfa
};
static unsigned char CAROL_OUTPUT_ONE[32] = {
    0xb7, 0xf3, 0xc6, 0x79, 0x30, 0x4a, 0xef, 0x8c,
    0xc0, 0xc7, 0x61, 0xf1, 0x00, 0x99, 0xdd, 0x7b,
    0x20, 0x65, 0x20, 0xd7, 0x11, 0x6f, 0xb7, 0x91,
    0xee, 0x74, 0x54, 0xa2, 0xfc, 0x22, 0x79, 0xf4
};
static unsigned char CAROL_OUTPUT_TWO[32] = {
    0x4b, 0x81, 0x34, 0x5d, 0x53, 0x89, 0xba, 0xa3,
    0xd8, 0x93, 0xe2, 0xfb, 0xe7, 0x08, 0xdd, 0x6d,
    0x82, 0xdc, 0xd8, 0x49, 0xab, 0x03, 0xc1, 0xdb,
    0x68, 0xbe, 0xc7, 0xe9, 0x2a, 0x45, 0xfa, 0xc5
};
static unsigned char SMALLEST_OUTPOINT[36] = {
    0x16, 0x9e, 0x1e, 0x83, 0xe9, 0x30, 0x85, 0x33, 0x91,
    0xbc, 0x6f, 0x35, 0xf6, 0x05, 0xc6, 0x75, 0x4c, 0xfe,
    0xad, 0x57, 0xcf, 0x83, 0x87, 0x63, 0x9d, 0x3b, 0x40,
    0x96, 0xc5, 0x4f, 0x18, 0xf4, 0x00, 0x00, 0x00, 0x00
};
static unsigned char ALICE_SECKEY[32] = {
    0xea, 0xdc, 0x78, 0x16, 0x5f, 0xf1, 0xf8, 0xea,
    0x94, 0xad, 0x7c, 0xfd, 0xc5, 0x49, 0x90, 0x73,
    0x8a, 0x4c, 0x53, 0xf6, 0xe0, 0x50, 0x7b, 0x42,
    0x15, 0x42, 0x01, 0xb8, 0xe5, 0xdf, 0xf3, 0xb1
};

static void test_recipient_sort_helper(unsigned char (*sp_addresses[3])[2][33], unsigned char (*sp_outputs[3])[32]) {
    unsigned char const *seckey_ptrs[1];
    secp256k1_silentpayments_recipient recipients[3];
    const secp256k1_silentpayments_recipient *recipient_ptrs[3];
    secp256k1_xonly_pubkey generated_outputs[3];
    secp256k1_xonly_pubkey *generated_output_ptrs[3];
    unsigned char xonly_ser[32];
    size_t i;
    int ret;

    seckey_ptrs[0] = ALICE_SECKEY;
    for (i = 0; i < 3; i++) {
        CHECK(secp256k1_ec_pubkey_parse(CTX, &recipients[i].scan_pubkey, (*sp_addresses[i])[0], 33));
        CHECK(secp256k1_ec_pubkey_parse(CTX, &recipients[i].spend_pubkey,(*sp_addresses[i])[1], 33));
        recipients[i].index = i;
        recipient_ptrs[i] = &recipients[i];
        generated_output_ptrs[i] = &generated_outputs[i];
    }
    ret = secp256k1_silentpayments_sender_create_outputs(CTX,
        generated_output_ptrs,
        recipient_ptrs, 3,
        SMALLEST_OUTPOINT,
        NULL, 0,
        seckey_ptrs, 1
    );
    CHECK(ret == 1);
    for (i = 0; i < 3; i++) {
        secp256k1_xonly_pubkey_serialize(CTX, xonly_ser, &generated_outputs[i]);
        CHECK(secp256k1_memcmp_var(xonly_ser, (*sp_outputs[i]), 32) == 0);
    }
}

static void test_recipient_sort(void) {
    unsigned char (*sp_addresses[3])[2][33];
    unsigned char (*sp_outputs[3])[32];

    /* With a fixed set of addresses and a fixed set of inputs,
     * test that we always get the same outputs, regardless of the ordering
     * of the recipients
     */
    sp_addresses[0] = &CAROL_ADDRESS;
    sp_addresses[1] = &BOB_ADDRESS;
    sp_addresses[2] = &CAROL_ADDRESS;

    sp_outputs[0] = &CAROL_OUTPUT_ONE;
    sp_outputs[1] = &BOB_OUTPUT;
    sp_outputs[2] = &CAROL_OUTPUT_TWO;
    test_recipient_sort_helper(sp_addresses, sp_outputs);

    sp_addresses[0] = &CAROL_ADDRESS;
    sp_addresses[1] = &CAROL_ADDRESS;
    sp_addresses[2] = &BOB_ADDRESS;

    sp_outputs[0] = &CAROL_OUTPUT_ONE;
    sp_outputs[1] = &CAROL_OUTPUT_TWO;
    sp_outputs[2] = &BOB_OUTPUT;
    test_recipient_sort_helper(sp_addresses, sp_outputs);

    sp_addresses[0] = &BOB_ADDRESS;
    sp_addresses[1] = &CAROL_ADDRESS;
    sp_addresses[2] = &CAROL_ADDRESS;

    /* Note: in this case, the second output for Carol comes before the first.
     * This is because heapsort is an unstable sorting algorithm, i.e., the ordering
     * of identical elements is not guaranteed to be preserved
     */
    sp_outputs[0] = &BOB_OUTPUT;
    sp_outputs[1] = &CAROL_OUTPUT_TWO;
    sp_outputs[2] = &CAROL_OUTPUT_ONE;
    test_recipient_sort_helper(sp_addresses, sp_outputs);
}

static void test_send_api(void) {
    unsigned char (*sp_addresses[2])[2][33];
    unsigned char const *p[1];
    secp256k1_keypair const *t[1];
    secp256k1_silentpayments_recipient r[2];
    const secp256k1_silentpayments_recipient *rp[2];
    secp256k1_xonly_pubkey o[2];
    secp256k1_xonly_pubkey *op[2];
    secp256k1_keypair taproot;
    size_t i;

    /* Set up Bob and Carol as the recipients */
    sp_addresses[0] = &BOB_ADDRESS;
    sp_addresses[1] = &CAROL_ADDRESS;
    for (i = 0; i < 2; i++) {
        CHECK(secp256k1_ec_pubkey_parse(CTX, &r[i].scan_pubkey, (*sp_addresses[i])[0], 33));
        CHECK(secp256k1_ec_pubkey_parse(CTX, &r[i].spend_pubkey,(*sp_addresses[i])[1], 33));
        /* Set the index value incorrectly */
        r[i].index = 0;
        rp[i] = &r[i];
        op[i] = &o[i];
    }
    /* Set up a taproot key and a plain key for Alice */
    CHECK(secp256k1_keypair_create(CTX, &taproot, ALICE_SECKEY));
    t[0] = &taproot;
    p[0] = ALICE_SECKEY;

    /* Fails if the index is set incorrectly */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));

    /* Set the index correctly for the next tests */
    for (i = 0; i < 2; i++) {
        r[i].index = i;
    }
    CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));

    /* Check that null arguments are handled */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, NULL, rp, 2, SMALLEST_OUTPOINT, t, 1, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, NULL, 2, SMALLEST_OUTPOINT, t, 1, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, NULL, t, 1, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 1, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, t, 1, NULL, 1));

    /* Check correct context is used */
    CHECK_ILLEGAL(STATIC_CTX, secp256k1_silentpayments_sender_create_outputs(STATIC_CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));

    /* Check that array arguments are verified */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, NULL, 0));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 0, SMALLEST_OUTPOINT, NULL, 0, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, t, 0, p, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, t, 1, p, 0));

    /* Create malformed keys for Alice by using a key that will overflow */
    CHECK(secp256k1_ec_seckey_verify(CTX, secp256k1_group_order_bytes) == 0);
    p[0] = secp256k1_group_order_bytes;
    CHECK(secp256k1_keypair_create(CTX, &taproot, ALICE_SECKEY));
    /* Malleate the keypair object so that the secret key is all zeros. We need to keep
     * public key as is since it is loaded first and would hit an ARG_CHECK if invalid.
     */
    memset(&taproot.data[0], 0, 32);
    /* Check that an invalid plain secret key is caught */
    CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);
    /* Check that an invalid keypair is caught */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, t, 1, NULL, 0));
    /* Create malformed keys for Alice by using a zero'd seckey */
    p[0] = MALFORMED_SECKEY;
    CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);
    p[0] = ALICE_SECKEY;
    /* Create malformed recipients by setting all of the public key bytes to zero.
     * Realistically, this would never happen since a bad public key would get caught when
     * trying to parse the public key with _ec_pubkey_parse
     */
    {
         secp256k1_pubkey tmp = r[1].spend_pubkey;
         memset(&r[1].spend_pubkey, 0, sizeof(r[1].spend_pubkey));
         CHECK_ILLEGAL(CTX, secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1));
         r[1].spend_pubkey = tmp;
    }
    {
        secp256k1_pubkey tmp = r[1].scan_pubkey;
        int32_t ecount = 0;

        memset(&r[1].scan_pubkey, 0, sizeof(r[1].scan_pubkey));
        secp256k1_context_set_illegal_callback(CTX, counting_callback_fn, &ecount);
        CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);
        CHECK(ecount == 2);
        secp256k1_context_set_illegal_callback(CTX, NULL, NULL);
        r[1].scan_pubkey = tmp;
    }
    {
        unsigned char malformed_spend_key[32] = {
                0x83, 0xe1, 0x79, 0xdf, 0x51, 0xbb, 0xc9, 0x6f,
                0xfb, 0x59, 0xb6, 0x2e, 0x57, 0xcf, 0x4e, 0x54,
                0x71, 0x79, 0x04, 0x9c, 0x01, 0x47, 0x00, 0xfe,
                0x52, 0xef, 0x5f, 0x53, 0x76, 0x39, 0xec, 0xe0
        };
        secp256k1_pubkey neg_spend_pubkey;
        CHECK(secp256k1_ec_pubkey_create(CTX, &neg_spend_pubkey, malformed_spend_key));
        CHECK(secp256k1_ec_pubkey_negate(CTX, &neg_spend_pubkey));
        r[0].spend_pubkey = neg_spend_pubkey;
        for (i = 0; i < 2; i++) {
            r[i].index = i;
            rp[i] = &r[i];
        }
        CHECK(secp256k1_silentpayments_sender_create_outputs(CTX, op, rp, 2, SMALLEST_OUTPOINT, NULL, 0, p, 1) == 0);
    }
}

static void test_label_api(void) {
    secp256k1_pubkey l, s, ls, e; /* label pk, spend pk, labeled spend pk, expected labeled spend pk */
    unsigned char lt[32];         /* label tweak */
    const unsigned char expected[33] = {
        0x03, 0xdc, 0x7f, 0x09, 0x9a, 0xbe, 0x95, 0x7a,
        0x58, 0x43, 0xd2, 0xb6, 0xbb, 0x35, 0x79, 0x61,
        0x5c, 0x60, 0x36, 0xa4, 0x9b, 0x86, 0xf4, 0xbe,
        0x46, 0x38, 0x60, 0x28, 0xa8, 0x1a, 0x77, 0xd4,
        0x91
    };

    /* Create a label and labeled spend public key, verify we get the expected result */
    CHECK(secp256k1_ec_pubkey_parse(CTX, &s, BOB_ADDRESS[1], 33));
    CHECK(secp256k1_silentpayments_recipient_create_label(CTX, &l, lt, ALICE_SECKEY, 1));
    CHECK(secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &l));
    CHECK(secp256k1_ec_pubkey_parse(CTX, &e, expected, 33));
    CHECK(secp256k1_ec_pubkey_cmp(CTX, &ls, &e) == 0);

    /* Check null values are handled */
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_label(CTX, NULL, lt, ALICE_SECKEY, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_label(CTX, &l, NULL, ALICE_SECKEY, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_label(CTX, &l, lt, NULL, 1));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, NULL, &s, &l));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, NULL, &l));
    CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, NULL));
    /* Check that creating a label with an invalid scan key fails */
    CHECK(secp256k1_silentpayments_recipient_create_label(CTX, &l, lt, MALFORMED_SECKEY, 1) == 0);
    CHECK(secp256k1_silentpayments_recipient_create_label(CTX, &l, lt, secp256k1_group_order_bytes, 1) == 0);
    /* Check for malformed spend and label public keys, i.e., any single pubkey is malformed or the public
     * keys are valid but sum up to zero.
     */
    {
        secp256k1_pubkey neg_spend_pubkey = s;
        CHECK(secp256k1_ec_pubkey_negate(CTX, &neg_spend_pubkey));
        CHECK(secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &neg_spend_pubkey) == 0);
        /* Also test with a malformed spend public key. */
        memset(&s, 0, sizeof(s));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &neg_spend_pubkey));
        /* Reset s back to a valid public key for the next test. */
        CHECK(secp256k1_ec_pubkey_parse(CTX, &s, BOB_ADDRESS[1], 33));
        memset(&l, 0, sizeof(l));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &l));
        /* Reset l back to a valid public key for the next test */
        CHECK(secp256k1_silentpayments_recipient_create_label(CTX, &l, lt, ALICE_SECKEY, 1));
        memset(&s, 0, sizeof(s));
        CHECK_ILLEGAL(CTX, secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(CTX, &ls, &s, &l));
    }
}

/* --- Test registry --- */
static const struct tf_test_entry tests_silentpayments[] = {
    CASE1(test_recipient_sort),
    CASE1(test_send_api),
    CASE1(test_label_api),
};

#endif
