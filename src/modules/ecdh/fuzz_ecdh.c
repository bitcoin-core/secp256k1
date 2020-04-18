/**********************************************************************
 * Copyright (c) 2020 Elichai Turkel                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef SECP256K1_MODULE_ECDH_FUZZ_IMPL_H
#define SECP256K1_MODULE_ECDH_FUZZ_IMPL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "include/secp256k1_ecdh.h"
#include "src/util.h"
#include "src/fuzz/fuzz.h"

static secp256k1_context* ctx = NULL;

void initialize() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    CHECK(ctx != NULL);
}
static int ecdh_hash_function_custom(unsigned char *output65, const unsigned char *x, const unsigned char *y, void *data) {
    (void)data;
    /* Save x and y as uncompressed public key */
    output65[0] = 0x04;
    memcpy(output65 + 1, x, 32);
    memcpy(output65 + 33, y, 32);
    return 1;
}

void test_one_input(fuzzed_data_provider* provider) {
    /* Make sure ECDH(seckey,pubkey) == seckey * pubkey */
    {
        const unsigned char* seckey;
        secp256k1_pubkey pubkey;

        seckey = consume_seckey(provider);
        if (seckey && consume_pubkey(provider, &pubkey)) {
            unsigned char result1[65];
            unsigned char result2[65];
            size_t n = sizeof(result2);
            CHECK(secp256k1_ecdh(ctx, result1, &pubkey, seckey, ecdh_hash_function_custom, NULL) == 1);

            CHECK(secp256k1_ec_pubkey_tweak_mul(ctx, &pubkey, seckey) == 1);
            CHECK(secp256k1_ec_pubkey_serialize(ctx, result2, &n, &pubkey, SECP256K1_EC_UNCOMPRESSED) == 1);
            CHECK(n == sizeof(result2));
            CHECK(memcmp(result1, result2, n) == 0);
        }
    }
    /* Make sure ECDH(seckey1, pubkey2) == ECDH(seckey2, pubkey1) */
    {
        const unsigned char* seckey1;
        const unsigned char* seckey2;
        seckey1 = consume_seckey(provider);
        seckey2 = consume_seckey(provider);
        if (seckey1 && seckey2) {
            secp256k1_pubkey pubkey1, pubkey2;
            unsigned char result1[32];
            unsigned char result2[32];

            CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey1, seckey1) == 1);
            CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey2, seckey2) == 1);

            CHECK(secp256k1_ecdh(ctx, result1, &pubkey1, seckey2, NULL, NULL) == 1);
            CHECK(secp256k1_ecdh(ctx, result2, &pubkey2, seckey1, NULL, NULL) == 1);

            CHECK(memcmp(result1, result2, sizeof(result1)) == 0);
        }
    }
}

#endif /* SECP256K1_MODULE_ECDH_FUZZ_IMPL_H */
