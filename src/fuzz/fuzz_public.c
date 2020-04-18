/**********************************************************************
 * Copyright (c) 2020 Elichai Turkel                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "include/secp256k1_recovery.h"
#include "src/util.h"
#include "src/fuzz/fuzz.h"

static secp256k1_context* ctx = NULL;

void initialize() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    CHECK(ctx != NULL);
}

void test_one_input(fuzzed_data_provider* provider) {
    /* Create and destroy a scratch space */
    {
        const unsigned char* byte;
        byte = consume_bytes(provider, 1);
        if (byte) {
            secp256k1_scratch_space_destroy(ctx, secp256k1_scratch_space_create(ctx, *byte));
        }
    }
    /* Randomize the context */
    {
        const unsigned char* randomize;
        randomize = consume_bytes(provider, 32);
        if (randomize) {
            CHECK(secp256k1_context_randomize(ctx, randomize) == 1);
        }
    }
    /* Sign & Verify */
    {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig, sig_normalized;
        const unsigned char* seckey;
        const unsigned char* msg;
        seckey = consume_seckey(provider);
        msg = consume_bytes(provider, 32);
        if (seckey && msg) {
            CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 1);
            CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, seckey, NULL, NULL) == 1);
            CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg, &pubkey) == 1);

            /* libsecp256k1, only generates normalized signatures, check that */
            CHECK(secp256k1_ecdsa_signature_normalize(ctx, &sig_normalized, &sig) == 0);
            CHECK(memcmp(&sig, &sig_normalized, sizeof(sig)) == 0);
        }
    }
    /* Check valid pubkey compact parsing + serializing */
    {
        secp256k1_pubkey pubkey;
        if (consume_pubkey(provider, &pubkey)) {
            unsigned char serialized_pubkey[65];
            secp256k1_pubkey new_pubkey;
            size_t n = sizeof(serialized_pubkey);
            unsigned char compressed;

            CHECK(secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &n, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
            CHECK(n == 33);
            CHECK(secp256k1_ec_pubkey_parse(ctx, &new_pubkey, serialized_pubkey, n) == 1);
            CHECK(memcmp(&pubkey, &new_pubkey, sizeof(pubkey)) == 0);
            compressed = serialized_pubkey[0];
            n = 65;
            CHECK(secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &n, &pubkey, SECP256K1_EC_UNCOMPRESSED) == 1);
            CHECK(n == 65);
            CHECK(secp256k1_ec_pubkey_parse(ctx, &new_pubkey, serialized_pubkey, n) == 1);
            CHECK(memcmp(&pubkey, &new_pubkey, sizeof(pubkey)) == 0);
            serialized_pubkey[0] += compressed;
            CHECK(secp256k1_ec_pubkey_parse(ctx, &new_pubkey, serialized_pubkey, n) == 1);
            CHECK(memcmp(&pubkey, &new_pubkey, sizeof(pubkey)) == 0);
        }
    }
    /* Check valid pubkey DER parsing + serializing */
    {
        unsigned char serialized_sig[72];
        secp256k1_ecdsa_signature sig, newsig;
        size_t n = sizeof(serialized_sig);
        const unsigned char* input64;
        input64 = consume_bytes(provider, 64);
        /* This should succeed as long as r and s (first and second 32 bytes) aren't bigger than the order */
        if (input64 && secp256k1_ecdsa_signature_parse_compact(ctx, &sig, input64)) {
            CHECK(secp256k1_ecdsa_signature_serialize_der(ctx, serialized_sig, &n, &sig) == 1);
            CHECK(secp256k1_ecdsa_signature_parse_der(ctx, &newsig, serialized_sig, n) == 1);
            CHECK(memcmp(&sig, &newsig, sizeof(sig)) == 0);
            CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_sig, &sig) == 1);
            CHECK(secp256k1_ecdsa_signature_parse_compact(ctx, &newsig, serialized_sig) == 1);
            CHECK(memcmp(&sig, &newsig, sizeof(sig)) == 0);
        }
    }

    /* Double negating a seckey should stay equal */
    {
        const unsigned char* seckey;
        seckey = consume_seckey(provider);
        if (seckey) {
            unsigned char seckey_copy[32];
            memcpy(seckey_copy, seckey, sizeof(seckey_copy));

            CHECK(secp256k1_ec_privkey_negate(ctx, seckey_copy) == 1);
            CHECK(secp256k1_ec_privkey_negate(ctx, seckey_copy) == 1);
            CHECK(memcmp(seckey_copy, seckey, sizeof(seckey_copy)) == 0);
        }
    }
    /* Double negating a pubkey should stay equal */
    {
        secp256k1_pubkey pubkey;
        if (consume_pubkey(provider, &pubkey)) {
            secp256k1_pubkey pubkey_copy;
            pubkey_copy = pubkey;

            CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey) == 1);
            CHECK(secp256k1_ec_pubkey_negate(ctx, &pubkey) == 1);
            CHECK(memcmp(&pubkey_copy, &pubkey, sizeof(pubkey_copy)) == 0);
        }
    }
    /* Check that Pubkey(seckey1+seckey2) == Pubkey(seckey1) + Pubkey(seckey2). */
    {
        const unsigned char* seckey1;
        const unsigned char* seckey2;
        seckey1 = consume_seckey(provider);
        seckey2 = consume_seckey(provider);
        if (seckey1 && seckey2) {
            secp256k1_pubkey pubkey1, pubkey2, combined_pubkey1, combined_pubkey2;
            unsigned char combined_seckey[32];
            const secp256k1_pubkey* pubkey_ptrs[2];


            memcpy(combined_seckey, seckey1, sizeof(combined_seckey));
            CHECK(secp256k1_ec_privkey_tweak_add(ctx, combined_seckey, seckey2) == 1);
            CHECK(secp256k1_ec_pubkey_create(ctx, &combined_pubkey2, combined_seckey) == 1);

            CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey1, seckey1) == 1);
            CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, seckey2) == 1);

            pubkey_ptrs[0] = &pubkey1; pubkey_ptrs[1] = &pubkey2;
            CHECK(secp256k1_ec_pubkey_combine(ctx, &combined_pubkey1, pubkey_ptrs, 2) == 1);

            CHECK(memcmp(&combined_pubkey1, &combined_pubkey2, sizeof(combined_pubkey1)) == 0);

            CHECK(secp256k1_ec_pubkey_tweak_add(ctx, &pubkey1, seckey2) == 1);
            CHECK(memcmp(&combined_pubkey1, &pubkey1, sizeof(combined_pubkey1)) == 0);
        }
    }
    /* Check that Pubkey(seckey1)*seckey2 == Pubkey(seckey1 * seckey2) */
    {
        const unsigned char* seckey1;
        const unsigned char* seckey2;
        seckey1 = consume_seckey(provider);
        seckey2 = consume_seckey(provider);
        if (seckey1 && seckey2) {
            secp256k1_pubkey mul_pubkey1, mul_pubkey2;
            unsigned char mul_seckey[32];

            CHECK(secp256k1_ec_pubkey_create(ctx, &mul_pubkey1, seckey1) == 1);
            CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &mul_pubkey1, seckey2) == 1);

            memcpy(&mul_seckey, seckey1, sizeof(mul_seckey));
            CHECK(secp256k1_ec_privkey_tweak_mul(ctx, mul_seckey, seckey2) == 1);
            CHECK(secp256k1_ec_pubkey_create(ctx, &mul_pubkey2, mul_seckey) == 1);

            CHECK(memcmp(&mul_pubkey1, &mul_pubkey2, sizeof(mul_pubkey1)) == 0);
        }
    }
    /*Fuzz Garbage through parsing functions */
    {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        const unsigned char* random32;
        const unsigned char* random64;
        const unsigned char* tmp;
        unsigned char random33[33], random65[65];
        int ret = 0;
        random32 = consume_bytes(provider, 32);
        if (random32) {
            ret |= secp256k1_ec_seckey_verify(ctx, random32);
        }
        tmp = consume_bytes(provider, 33);
        if (tmp) {
            memcpy(random33, tmp, sizeof(random33));
            ret |= secp256k1_ec_pubkey_parse(ctx, &pubkey, random33, 33);
            random33[0] = 0x02;
            ret |= secp256k1_ec_pubkey_parse(ctx, &pubkey, random33, 33);
            random33[0] = 0x03;
            ret |= secp256k1_ec_pubkey_parse(ctx, &pubkey, random33, 33);
        }
        tmp = consume_bytes(provider, 65);
        if (tmp) {
            memcpy(random65, tmp, sizeof(random65));
            ret |= secp256k1_ec_pubkey_parse(ctx, &pubkey, random65, 65);
            random65[0] = 0x04;
            ret |= secp256k1_ec_pubkey_parse(ctx, &pubkey, random65, 65);
            random65[0] = 0x06;
            ret |= secp256k1_ec_pubkey_parse(ctx, &pubkey, random65, 65);
            random65[0] = 0x07;
            ret |= secp256k1_ec_pubkey_parse(ctx, &pubkey, random65, 65);
        }
        random64 = consume_bytes(provider, 64);
        if (random64) {
            int tmp_ret = secp256k1_ecdsa_signature_parse_compact(ctx, &sig, random64);
            if(tmp_ret) {
                /* It's statistically impossible to randomally find a random sig that will validate a given msg+key. */
                const unsigned char secret_msg[32] = "This is the super secret message";
                const unsigned char predefined_pubkey[33] = "\002A public key without private key";
                CHECK(secp256k1_ec_pubkey_parse(ctx, &pubkey, predefined_pubkey, sizeof(predefined_pubkey)) == 1);
                CHECK(secp256k1_ecdsa_verify(ctx, &sig, secret_msg, &pubkey) == 0);
            }
            ret |= tmp_ret;
        }
        /* Fuzz the rest of the data into the parse_der function */
        ret |= secp256k1_ecdsa_signature_parse_der(ctx, &sig, provider->data, provider->remaining);
        CHECK(ret == 0 || ret == 1);
    }
}
