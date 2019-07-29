/**********************************************************************
 * Copyright (c) 2019-2020 Marko Bencun, Jonas Nick                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_ECDSA_SIGN_TO_CONTRACT_TESTS_H
#define SECP256K1_MODULE_ECDSA_SIGN_TO_CONTRACT_TESTS_H

typedef struct {
    unsigned char s2c_data[32];
    /* host_commitment = sha256(<s2c_data><ndata>) */
    unsigned char host_commitment[32];
    /* expected_pubnonce = host_commitment*G */
    unsigned char expected_pubnonce[33];
} ecdsa_s2c_test;

/* When using sign-to-contract commitments, the nonce function is fixed, so we can use fixtures to test. */
static ecdsa_s2c_test ecdsa_s2c_tests[] = {
    {
        "\x1b\xf6\xfb\x42\xf4\x1e\xb8\x76\xc4\xd7\xaa\x0d\x67\x24\x2b\x00\xba\xab\x99\xdc\x20\x84\x49\x3e\x4e\x63\x27\x7f\xa1\xf7\x7f\x22",
        "\xcd\xfe\xb3\xad\x27\x00\x21\x9e\xf7\xe1\xd3\x48\x3e\x31\xe0\xbf\x19\x34\x50\xb3\x77\x41\x58\xaa\x5d\x0f\x95\xb9\xb6\x5b\xaf\xc2",
        "\x02\x3d\xce\xb4\xef\x0d\x4f\x59\x98\xf2\xd3\x02\xdb\xfb\x17\x86\x24\xf6\x3e\x17\x5c\xd2\x13\xf5\xf8\x9a\x30\xce\xe4\x50\x17\x4c\x07",
    },
    {
        "\x35\x19\x9a\x8f\xbf\x84\xad\x6e\xf6\x9a\x18\x4c\x1b\x19\x28\x5b\xef\xbe\x06\xe6\x0b\x62\x64\xe6\xd3\x73\x89\x3f\x68\x55\xe2\x4a",
        "\x87\x62\x71\xd6\xfd\xc7\x57\x5a\x44\xb9\x81\x0a\xb2\xea\x8f\x54\xb5\x77\xe3\x35\x86\xb3\x4c\x0d\xc5\xf3\x5f\xf6\xbd\xb8\xeb\x6c",
        "\x02\x61\x10\x22\x34\xd2\x03\xe6\x11\xaa\xe7\x1e\x4e\x04\x30\xc2\xf1\x28\x6d\x9c\x2f\x4c\x96\x4f\x54\x0d\x03\x5c\xed\x94\xd7\x42\x6f",
    },
};

static void test_ecdsa_s2c_original_pubnonce(void) {
    size_t i;
    unsigned char privkey[32] = {
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
        0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55, 0x55,
    };
    unsigned char message[32] = {
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
        0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88, 0x88,
    };
    secp256k1_ecdsa_signature signature;
    secp256k1_s2c_opening s2c_opening;
    unsigned char pubnonce[33];
    /*
      Check that original pubnonce is derived from s2c_data and ndata.
    */
    for (i = 0; i < sizeof(ecdsa_s2c_tests) / sizeof(ecdsa_s2c_tests[0]); i++) {
        size_t pubnonce_size = 33;
        const ecdsa_s2c_test *test = &ecdsa_s2c_tests[i];
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, &s2c_opening, message, privkey, test->s2c_data) == 1);
        CHECK(secp256k1_ec_pubkey_serialize(ctx, pubnonce, &pubnonce_size, &s2c_opening.original_pubnonce, SECP256K1_EC_COMPRESSED) == 1);
        CHECK(memcmp(test->expected_pubnonce, pubnonce, pubnonce_size) == 0);
    }
}

static void test_ecdsa_s2c_api(void) {
    secp256k1_ecdsa_signature signature;
    unsigned char privkey[32] = {1};
    unsigned char message[32] = {0};
    unsigned char s2c_data[32] = {0};
    secp256k1_s2c_opening s2c_opening;

    secp256k1_context *none = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_context *sign = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
    secp256k1_context *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    secp256k1_context *both = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    int ecount = 0;
    secp256k1_context_set_illegal_callback(none, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(sign, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(vrfy, counting_illegal_callback_fn, &ecount);
    secp256k1_context_set_illegal_callback(both, counting_illegal_callback_fn, &ecount);

    {
        ecount = 0;
        CHECK(secp256k1_ecdsa_s2c_sign(none, &signature, NULL, message, privkey, NULL) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_ecdsa_s2c_sign(sign, &signature, NULL, message, privkey, NULL) == 1);
        CHECK(ecount == 1);
        CHECK(secp256k1_ecdsa_s2c_sign(vrfy, &signature, NULL, message, privkey, NULL) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_ecdsa_s2c_sign(both, &signature, NULL, message, privkey, NULL) == 1);
        CHECK(ecount == 2);
    }
    { /* message, signature, seckey */
        ecount = 0;
        CHECK(secp256k1_ecdsa_s2c_sign(sign, NULL, NULL, message, privkey, NULL) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_ecdsa_s2c_sign(sign, &signature, NULL, NULL, privkey, NULL) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_ecdsa_s2c_sign(sign, &signature, NULL, message, NULL, NULL) == 0);
        CHECK(ecount == 3);
    }
    { /* either both opening and s2c_data are provided or none */
        ecount = 0;
        CHECK(secp256k1_ecdsa_s2c_sign(sign, &signature, NULL, message, privkey, NULL) == 1);
        CHECK(ecount == 0);
        CHECK(secp256k1_ecdsa_s2c_sign(sign, &signature, &s2c_opening, message, privkey, s2c_data) == 1);
        CHECK(ecount == 0);
        CHECK(secp256k1_ecdsa_s2c_sign(sign, &signature, NULL, message, privkey, s2c_data) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_ecdsa_s2c_sign(sign, &signature, &s2c_opening, message, privkey, NULL) == 0);
        CHECK(ecount == 2);
    }
    { /* verify_commit, ctx */
        ecount = 0;
        CHECK(secp256k1_ecdsa_s2c_sign(sign, &signature, &s2c_opening, message, privkey, s2c_data) == 1);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(none, &signature, s2c_data, &s2c_opening) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(sign, &signature, s2c_data, &s2c_opening) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(vrfy, &signature, s2c_data, &s2c_opening) == 1);
        CHECK(ecount == 2);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(both, &signature, s2c_data, &s2c_opening) == 1);
        CHECK(ecount == 2);
    }
    { /* verify_commit, NULL signature, s2c_data, s2c_opening */
        ecount = 0;
        CHECK(secp256k1_ecdsa_s2c_sign(sign, &signature, &s2c_opening, message, privkey, s2c_data) == 1);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(vrfy, NULL, s2c_data, &s2c_opening) == 0);
        CHECK(ecount == 1);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(vrfy, &signature, NULL, &s2c_opening) == 0);
        CHECK(ecount == 2);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(vrfy, &signature, s2c_data, NULL) == 0);
        CHECK(ecount == 3);
    }
    { /* verify_commit, invalid opening */
        secp256k1_s2c_opening invalid_opening = {0};
        ecount = 0;
        CHECK(secp256k1_ecdsa_s2c_verify_commit(vrfy, &signature, s2c_data, &invalid_opening) == 0);
        CHECK(ecount == 1);
    }
}

static void test_ecdsa_s2c_sign_verify(void) {
    unsigned char privkey[32];
    unsigned char zero_privkey[32] = {0};
    unsigned char overflow_privkey[32] = "\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff\xff";
    secp256k1_pubkey pubkey;
    unsigned char message[32];
    unsigned char noncedata[32];
    unsigned char s2c_data[32];
    unsigned char s2c_data2[32];
    secp256k1_ecdsa_signature signature;
    secp256k1_ecdsa_signature signature2;
    secp256k1_s2c_opening s2c_opening;


    /* Generate a random key, message, noncedata and s2c_data. */
    {
        secp256k1_scalar key;
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(privkey, &key);
        CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == 1);

        secp256k1_rand256_test(message);
        secp256k1_rand256_test(noncedata);
        secp256k1_rand256_test(s2c_data);
        secp256k1_rand256_test(s2c_data2);
    }

    { /* invalid privkeys */
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, NULL, message, zero_privkey, NULL) == 0);
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, NULL, message, overflow_privkey, NULL) == 0);
    }
    /* Check that sign-to-contract without any s2c_data results the same signature as normal sign. */
    {
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, NULL, message, privkey, NULL) == 1);
        CHECK(secp256k1_ecdsa_sign(ctx, &signature2, message, privkey, NULL, NULL) == 1);
        CHECK(memcmp(&signature, &signature2, sizeof(signature)) == 0);
    }

    /* Check that the sign-to-contract signature is valid, without s2c_data */
    {
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, NULL, message, privkey, NULL) == 1);
        CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);
    }
    /* Check that the sign-to-contract signature is valid, with s2c_data. Also check the commitment. */
    {
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, &s2c_opening, message, privkey, s2c_data) == 1);
        CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);
        CHECK(secp256k1_ecdsa_s2c_verify_commit(ctx, &signature, s2c_data, &s2c_opening) == 1);
    }
    /* Check that an invalid commitment does not verify */
    {
        unsigned char sigbytes[64];
        size_t i;
        CHECK(secp256k1_ecdsa_s2c_sign(ctx, &signature, &s2c_opening, message, privkey, s2c_data) == 1);
        CHECK(secp256k1_ecdsa_verify(ctx, &signature, message, &pubkey) == 1);

        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, sigbytes, &signature) == 1);
        for(i = 0; i < 32; i++) {
            /* change one byte */
            sigbytes[i] = (((int)sigbytes[i]) + 1) % 256;
            CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &signature, sigbytes) == 1);
            CHECK(secp256k1_ecdsa_s2c_verify_commit(ctx, &signature, s2c_data, &s2c_opening) == 0);
            /* revert */
            sigbytes[i] = (((int)sigbytes[i]) + 255) % 256;
        }
    }
}

static void run_ecdsa_sign_to_contract_tests(void) {
    int i;
    test_ecdsa_s2c_api();
    test_ecdsa_s2c_original_pubnonce();
    for (i = 0; i < count; i++) {
        test_ecdsa_s2c_sign_verify();
    }
}

#endif /* SECP256K1_MODULE_ECDSA_SIGN_TO_CONTRACT_TESTS_H */
