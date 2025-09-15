/*************************************************************************
 * Written in 2020-2022 by Elichai Turkel                                *
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_ecdh.h>

#include "examples_util.h"

int extract_x_coordinate(const secp256k1_context* ctx, const secp256k1_pubkey* pubkey, unsigned char x[32]) {
    unsigned char serialized[33];
    size_t len = sizeof(serialized);

    if (!secp256k1_ec_pubkey_serialize(ctx, serialized, &len, pubkey, SECP256K1_EC_COMPRESSED))
        return 0;

    memcpy(x, serialized + 1, 32);
    return 1;
}

int main(void) {
    unsigned char seckey1[32];
    unsigned char seckey2[32];
    unsigned char compressed_pubkey1[33];
    unsigned char compressed_pubkey2[33];
    unsigned char shared_secret1[32];
    unsigned char shared_secret2[32];
    unsigned char x1[32], x2[32];
    unsigned char randomize[32];
    int return_val;
    size_t len;
    secp256k1_pubkey pubkey1;
    secp256k1_pubkey pubkey2;

    /* Before we can call actual API functions, we need to create a "context". */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return EXIT_FAILURE;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail. */
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    /*** Key Generation ***/
    if (!fill_random(seckey1, sizeof(seckey1)) || !fill_random(seckey2, sizeof(seckey2))) {
        printf("Failed to generate randomness\n");
        return EXIT_FAILURE;
    }
    if (!secp256k1_ec_seckey_verify(ctx, seckey1) || !secp256k1_ec_seckey_verify(ctx, seckey2)) {
        printf("Generated secret key is invalid. This indicates an issue with the random number generator.\n");
        return EXIT_FAILURE;
    }

    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey1, seckey1);
    assert(return_val);
    return_val = secp256k1_ec_pubkey_create(ctx, &pubkey2, seckey2);
    assert(return_val);

    len = sizeof(compressed_pubkey1);
    return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey1, &len, &pubkey1, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    assert(len == sizeof(compressed_pubkey1));

    len = sizeof(compressed_pubkey2);
    return_val = secp256k1_ec_pubkey_serialize(ctx, compressed_pubkey2, &len, &pubkey2, SECP256K1_EC_COMPRESSED);
    assert(return_val);
    assert(len == sizeof(compressed_pubkey2));

    /*** Creating the shared secret ***/
    return_val = secp256k1_ecdh(ctx, shared_secret1, &pubkey2, seckey1, NULL, NULL);
    assert(return_val);

    return_val = secp256k1_ecdh(ctx, shared_secret2, &pubkey1, seckey2, NULL, NULL);
    assert(return_val);

    return_val = memcmp(shared_secret1, shared_secret2, sizeof(shared_secret1));
    assert(return_val == 0);

    /* Извлекаем X-координату */
    assert(extract_x_coordinate(ctx, &pubkey1, x1));
    assert(extract_x_coordinate(ctx, &pubkey2, x2));

    printf("Secret Key1: ");
    print_hex(seckey1, sizeof(seckey1));
    printf("Compressed Pubkey1: ");
    print_hex(compressed_pubkey1, sizeof(compressed_pubkey1));
    printf("X-coordinate Pubkey1: ");
    print_hex(x1, sizeof(x1));

    printf("\nSecret Key2: ");
    print_hex(seckey2, sizeof(seckey2));
    printf("Compressed Pubkey2: ");
    print_hex(compressed_pubkey2, sizeof(compressed_pubkey2));
    printf("X-coordinate Pubkey2: ");
    print_hex(x2, sizeof(x2));

    printf("\nShared Secret: ");
    print_hex(shared_secret1, sizeof(shared_secret1));

    secp256k1_context_destroy(ctx);

    secure_erase(seckey1, sizeof(seckey1));
    secure_erase(seckey2, sizeof(seckey2));
    secure_erase(shared_secret1, sizeof(shared_secret1));
    secure_erase(shared_secret2, sizeof(shared_secret2));

    return EXIT_SUCCESS;
}
