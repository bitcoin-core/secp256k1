/***********************************************************************
 * Copyright (c) 2020 Elichai Turkel                                   *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ECDH_FUZZ_H
#define SECP256K1_MODULE_ECDH_FUZZ_H

#include "../../../include/secp256k1_ecdh.h"

static int fuzz_ecdh_hash_function_custom(unsigned char *output65, const unsigned char *x, const unsigned char *y, void *data) {
    (void)data;
    /* Save x and y as uncompressed public key */
    output65[0] = 0x04;
    memcpy(output65 + 1, x, 32);
    memcpy(output65 + 33, y, 32);
    return 1;
}

static void fuzz_ecdh(fuzz_data_provider *provider) {
    /* Make sure ECDH(seckey,pubkey) == seckey * pubkey */
    {
        const unsigned char *seckey;
        secp256k1_pubkey pubkey;

        seckey = fuzz_consume_seckey(provider);
        if (seckey && fuzz_consume_pubkey(provider, &pubkey)) {
            unsigned char result1[65];
            unsigned char result2[65];
            size_t n = sizeof(result2);
            CHECK(secp256k1_ecdh(fuzz_ctx, result1, &pubkey, seckey, fuzz_ecdh_hash_function_custom, NULL) == 1);

            CHECK(secp256k1_ec_pubkey_tweak_mul(fuzz_ctx, &pubkey, seckey) == 1);
            CHECK(secp256k1_ec_pubkey_serialize(fuzz_ctx, result2, &n, &pubkey, SECP256K1_EC_UNCOMPRESSED) == 1);
            CHECK(n == sizeof(result2));
            CHECK(secp256k1_memcmp_var(result1, result2, n) == 0);
        }
    }
    /* Make sure ECDH(seckey1, pubkey2) == ECDH(seckey2, pubkey1) */
    {
        const unsigned char *seckey1;
        const unsigned char *seckey2;
        seckey1 = fuzz_consume_seckey(provider);
        seckey2 = fuzz_consume_seckey(provider);
        if (seckey1 && seckey2) {
            secp256k1_pubkey pubkey1, pubkey2;
            unsigned char result1[32];
            unsigned char result2[32];

            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &pubkey1, seckey1) == 1);
            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &pubkey2, seckey2) == 1);

            CHECK(secp256k1_ecdh(fuzz_ctx, result1, &pubkey1, seckey2, NULL, NULL) == 1);
            CHECK(secp256k1_ecdh(fuzz_ctx, result2, &pubkey2, seckey1, NULL, NULL) == 1);

            CHECK(secp256k1_memcmp_var(result1, result2, sizeof(result1)) == 0);
        }
    }
}

#endif /* SECP256K1_MODULE_ECDH_FUZZ_H */
