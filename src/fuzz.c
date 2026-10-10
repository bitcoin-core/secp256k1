/***********************************************************************
 * Copyright (c) 2020 Elichai Turkel                                   *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>

#ifdef USE_EXTERNAL_DEFAULT_CALLBACKS
    #pragma message("Ignoring USE_EXTERNAL_CALLBACKS in fuzz target.")
    #undef USE_EXTERNAL_DEFAULT_CALLBACKS
#endif
#include "secp256k1.c"

#include "../include/secp256k1.h"
#include "util.h"

typedef struct {
    const unsigned char *data;
    size_t remaining;
} fuzz_data_provider;

static secp256k1_context *fuzz_ctx = NULL;

/* Checks that ret is 0 or 1, and returns it for use in conditions. */
static int fuzz_check_bool(int ret) {
    CHECK(ret == 0 || ret == 1);
    return ret;
}

/* If input parses, checks that it serializes back to input; hybrid 0x06/0x07 serializes as 0x04. */
static void fuzz_check_pubkey_parse(const unsigned char *input, size_t inputlen) {
    secp256k1_pubkey pubkey;
    unsigned char ser[65];
    size_t serlen = sizeof(ser);
    if (!fuzz_check_bool(secp256k1_ec_pubkey_parse(fuzz_ctx, &pubkey, input, inputlen))) {
        return;
    }
    CHECK(secp256k1_ec_pubkey_serialize(fuzz_ctx, ser, &serlen, &pubkey, inputlen == 33 ? SECP256K1_EC_COMPRESSED : SECP256K1_EC_UNCOMPRESSED) == 1);
    CHECK(serlen == inputlen);
    CHECK(ser[0] == ((input[0] == 0x06 || input[0] == 0x07) ? 0x04 : input[0]));
    CHECK(secp256k1_memcmp_var(ser + 1, input + 1, inputlen - 1) == 0);
}

/* Consumes num bytes from the provider, returns NULL if there's not enough data left. */
static const unsigned char *fuzz_consume_bytes(fuzz_data_provider *provider, size_t num) {
    const unsigned char *res = provider->data;
    if (num > provider->remaining) {
        return NULL;
    }
    provider->data += num;
    provider->remaining -= num;
    return res;
}

/* Consumes at least 32 bytes until it finds a valid seckey, returns NULL if there's not enough data left. */
static const unsigned char *fuzz_consume_seckey(fuzz_data_provider *provider) {
    const unsigned char *end = provider->data + provider->remaining;
    const unsigned char *seckey;
    if (provider->remaining < 32) {
        return NULL;
    }

    while (!fuzz_check_bool(secp256k1_ec_seckey_verify(secp256k1_context_static, provider->data))) {
        if (++provider->data > end - 32) {
            provider->remaining = end - provider->data;
            return NULL;
        }
    }
    seckey = provider->data;
    provider->data += 32;
    provider->remaining = end - provider->data;
    return seckey;
}

/* Consumes at least 33 bytes until it finds a valid pubkey, returns 1 on success and 0 if there's not enough data left
 * (about half of all uniformly random x coordinates are on the curve).
 */
static int fuzz_consume_pubkey(fuzz_data_provider *provider, secp256k1_pubkey *res) {
    const unsigned char *end = provider->data + provider->remaining;
    unsigned char pubkey[33];
    if (provider->remaining < 33) {
        return 0;
    }

    pubkey[0] = 0x02 + (provider->data[0] & 1);
    memcpy(pubkey + 1, provider->data + 1, 32);

    while (!fuzz_check_bool(secp256k1_ec_pubkey_parse(secp256k1_context_static, res, pubkey, 33))) {
        if (++provider->data > end - 33) {
            provider->remaining = end - provider->data;
            return 0;
        }
        pubkey[0] = 0x02 + (provider->data[0] & 1);
        memcpy(pubkey + 1, provider->data + 1, 32);
    }
    provider->data += 33;
    provider->remaining = end - provider->data;
    return 1;
}

static void fuzz_ecdsa(fuzz_data_provider *provider) {
    /* Randomize the context */
    {
        const unsigned char *randomize;
        randomize = fuzz_consume_bytes(provider, 32);
        if (randomize) {
            CHECK(secp256k1_context_randomize(fuzz_ctx, randomize) == 1);
        }
    }
    /* Sign & Verify */
    {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig, sig_normalized;
        const unsigned char *seckey;
        const unsigned char *msg;
        seckey = fuzz_consume_seckey(provider);
        msg = fuzz_consume_bytes(provider, 32);
        if (seckey && msg) {
            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &pubkey, seckey) == 1);
            CHECK(secp256k1_ecdsa_sign(fuzz_ctx, &sig, msg, seckey, NULL, NULL) == 1);
            CHECK(secp256k1_ecdsa_verify(fuzz_ctx, &sig, msg, &pubkey) == 1);

            /* libsecp256k1 only generates normalized signatures, check that */
            CHECK(secp256k1_ecdsa_signature_normalize(fuzz_ctx, &sig_normalized, &sig) == 0);
            CHECK(secp256k1_memcmp_var(&sig, &sig_normalized, sizeof(sig)) == 0);
        }
    }
    /* Check valid pubkey compact parsing + serializing */
    {
        secp256k1_pubkey pubkey;
        if (fuzz_consume_pubkey(provider, &pubkey)) {
            unsigned char serialized_pubkey[65];
            secp256k1_pubkey new_pubkey;
            size_t n = sizeof(serialized_pubkey);
            unsigned char compressed;

            CHECK(secp256k1_ec_pubkey_serialize(fuzz_ctx, serialized_pubkey, &n, &pubkey, SECP256K1_EC_COMPRESSED) == 1);
            CHECK(n == 33);
            CHECK(secp256k1_ec_pubkey_parse(fuzz_ctx, &new_pubkey, serialized_pubkey, n) == 1);
            CHECK(secp256k1_memcmp_var(&pubkey, &new_pubkey, sizeof(pubkey)) == 0);
            compressed = serialized_pubkey[0];
            n = 65;
            CHECK(secp256k1_ec_pubkey_serialize(fuzz_ctx, serialized_pubkey, &n, &pubkey, SECP256K1_EC_UNCOMPRESSED) == 1);
            CHECK(n == 65);
            CHECK(secp256k1_ec_pubkey_parse(fuzz_ctx, &new_pubkey, serialized_pubkey, n) == 1);
            CHECK(secp256k1_memcmp_var(&pubkey, &new_pubkey, sizeof(pubkey)) == 0);
            /* 0x04 + 0x02/0x03 is the hybrid prefix 0x06/0x07 */
            serialized_pubkey[0] += compressed;
            CHECK(secp256k1_ec_pubkey_parse(fuzz_ctx, &new_pubkey, serialized_pubkey, n) == 1);
            CHECK(secp256k1_memcmp_var(&pubkey, &new_pubkey, sizeof(pubkey)) == 0);
        }
    }
    /* Check valid signature DER parsing + serializing */
    {
        unsigned char serialized_sig[72];
        secp256k1_ecdsa_signature sig, newsig;
        size_t n = sizeof(serialized_sig);
        const unsigned char *input64;
        input64 = fuzz_consume_bytes(provider, 64);
        /* This should succeed as long as r and s (first and second 32 bytes) aren't bigger than the order */
        if (input64 && fuzz_check_bool(secp256k1_ecdsa_signature_parse_compact(fuzz_ctx, &sig, input64))) {
            CHECK(secp256k1_ecdsa_signature_serialize_der(fuzz_ctx, serialized_sig, &n, &sig) == 1);
            CHECK(secp256k1_ecdsa_signature_parse_der(fuzz_ctx, &newsig, serialized_sig, n) == 1);
            CHECK(secp256k1_memcmp_var(&sig, &newsig, sizeof(sig)) == 0);
            CHECK(secp256k1_ecdsa_signature_serialize_compact(fuzz_ctx, serialized_sig, &sig) == 1);
            CHECK(secp256k1_ecdsa_signature_parse_compact(fuzz_ctx, &newsig, serialized_sig) == 1);
            CHECK(secp256k1_memcmp_var(&sig, &newsig, sizeof(sig)) == 0);
        }
    }
    /* Double negating a seckey should stay equal */
    {
        const unsigned char *seckey;
        seckey = fuzz_consume_seckey(provider);
        if (seckey) {
            unsigned char seckey_copy[32];
            memcpy(seckey_copy, seckey, sizeof(seckey_copy));

            CHECK(secp256k1_ec_seckey_negate(fuzz_ctx, seckey_copy) == 1);
            CHECK(secp256k1_ec_seckey_negate(fuzz_ctx, seckey_copy) == 1);
            CHECK(secp256k1_memcmp_var(seckey_copy, seckey, sizeof(seckey_copy)) == 0);
        }
    }
    /* Double negating a pubkey should stay equal */
    {
        secp256k1_pubkey pubkey;
        if (fuzz_consume_pubkey(provider, &pubkey)) {
            secp256k1_pubkey pubkey_copy;
            pubkey_copy = pubkey;

            CHECK(secp256k1_ec_pubkey_negate(fuzz_ctx, &pubkey) == 1);
            CHECK(secp256k1_ec_pubkey_negate(fuzz_ctx, &pubkey) == 1);
            CHECK(secp256k1_memcmp_var(&pubkey_copy, &pubkey, sizeof(pubkey_copy)) == 0);
        }
    }
    /* Check that Pubkey(seckey1+seckey2) == Pubkey(seckey1) + Pubkey(seckey2). */
    {
        const unsigned char *seckey1;
        const unsigned char *seckey2;
        seckey1 = fuzz_consume_seckey(provider);
        seckey2 = fuzz_consume_seckey(provider);
        if (seckey1 && seckey2) {
            secp256k1_pubkey pubkey1, pubkey2, combined_pubkey1, combined_pubkey2;
            unsigned char combined_seckey[32];
            const secp256k1_pubkey *pubkey_ptrs[2];
            unsigned char neg_seckey1[32];
            int ret;

            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &pubkey1, seckey1) == 1);
            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &pubkey2, seckey2) == 1);
            pubkey_ptrs[0] = &pubkey1; pubkey_ptrs[1] = &pubkey2;

            /* All three fail together iff seckey2 == -seckey1 mod n. */
            memcpy(neg_seckey1, seckey1, sizeof(neg_seckey1));
            CHECK(secp256k1_ec_seckey_negate(fuzz_ctx, neg_seckey1) == 1);
            memcpy(combined_seckey, seckey1, sizeof(combined_seckey));
            ret = fuzz_check_bool(secp256k1_ec_seckey_tweak_add(fuzz_ctx, combined_seckey, seckey2));
            CHECK(ret == (secp256k1_memcmp_var(neg_seckey1, seckey2, sizeof(neg_seckey1)) != 0));
            CHECK(secp256k1_ec_pubkey_combine(fuzz_ctx, &combined_pubkey1, pubkey_ptrs, 2) == ret);
            CHECK(secp256k1_ec_pubkey_tweak_add(fuzz_ctx, &pubkey1, seckey2) == ret);
            if (ret) {
                CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &combined_pubkey2, combined_seckey) == 1);
                CHECK(secp256k1_memcmp_var(&combined_pubkey1, &combined_pubkey2, sizeof(combined_pubkey1)) == 0);
                CHECK(secp256k1_memcmp_var(&combined_pubkey1, &pubkey1, sizeof(combined_pubkey1)) == 0);
            }
        }
    }
    /* Check that Pubkey(seckey1)*seckey2 == Pubkey(seckey1 * seckey2) */
    {
        const unsigned char *seckey1;
        const unsigned char *seckey2;
        seckey1 = fuzz_consume_seckey(provider);
        seckey2 = fuzz_consume_seckey(provider);
        if (seckey1 && seckey2) {
            secp256k1_pubkey mul_pubkey1, mul_pubkey2;
            unsigned char mul_seckey[32];

            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &mul_pubkey1, seckey1) == 1);
            CHECK(secp256k1_ec_pubkey_tweak_mul(fuzz_ctx, &mul_pubkey1, seckey2) == 1);

            memcpy(mul_seckey, seckey1, sizeof(mul_seckey));
            CHECK(secp256k1_ec_seckey_tweak_mul(fuzz_ctx, mul_seckey, seckey2) == 1);
            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &mul_pubkey2, mul_seckey) == 1);

            CHECK(secp256k1_memcmp_var(&mul_pubkey1, &mul_pubkey2, sizeof(mul_pubkey1)) == 0);
        }
    }
    /* Fuzz garbage through parsing functions */
    {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        const unsigned char *random32;
        const unsigned char *random64;
        const unsigned char *tmp;
        unsigned char random33[33], random65[65];
        random32 = fuzz_consume_bytes(provider, 32);
        if (random32) {
            /* Both accept exactly the valid secret keys */
            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &pubkey, random32) == fuzz_check_bool(secp256k1_ec_seckey_verify(fuzz_ctx, random32)));
        }
        tmp = fuzz_consume_bytes(provider, 33);
        if (tmp) {
            memcpy(random33, tmp, sizeof(random33));
            fuzz_check_pubkey_parse(random33, 33);
            random33[0] = 0x02;
            fuzz_check_pubkey_parse(random33, 33);
            random33[0] = 0x03;
            fuzz_check_pubkey_parse(random33, 33);
        }
        tmp = fuzz_consume_bytes(provider, 65);
        if (tmp) {
            memcpy(random65, tmp, sizeof(random65));
            fuzz_check_pubkey_parse(random65, 65);
            random65[0] = 0x04;
            fuzz_check_pubkey_parse(random65, 65);
            random65[0] = 0x06;
            fuzz_check_pubkey_parse(random65, 65);
            random65[0] = 0x07;
            fuzz_check_pubkey_parse(random65, 65);
        }
        random64 = fuzz_consume_bytes(provider, 64);
        if (random64) {
            if (fuzz_check_bool(secp256k1_ecdsa_signature_parse_compact(fuzz_ctx, &sig, random64))) {
                /* It's statistically impossible to randomly find a sig that will validate a given msg+key. */
                const unsigned char secret_msg[33] = "This is the super secret message";
                const unsigned char predefined_pubkey[34] = "\002A public key without private key";
                CHECK(secp256k1_ec_pubkey_parse(fuzz_ctx, &pubkey, predefined_pubkey, 33) == 1);
                CHECK(secp256k1_ecdsa_verify(fuzz_ctx, &sig, secret_msg, &pubkey) == 0);
            }
        }
        /* Fuzz the rest of the data into the parse_der function */
        fuzz_check_bool(secp256k1_ecdsa_signature_parse_der(fuzz_ctx, &sig, provider->data, provider->remaining));
    }
}

#ifdef ENABLE_MODULE_ECDH
# include "modules/ecdh/fuzz_impl.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "modules/recovery/fuzz_impl.h"
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
# include "modules/extrakeys/fuzz_impl.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
# include "modules/schnorrsig/fuzz_impl.h"
#endif

#ifdef ENABLE_MODULE_MUSIG
# include "modules/musig/fuzz_impl.h"
#endif

#ifdef ENABLE_MODULE_ELLSWIFT
# include "modules/ellswift/fuzz_impl.h"
#endif

#ifdef ENABLE_MODULE_SILENTPAYMENTS
# include "modules/silentpayments/fuzz_impl.h"
#endif

typedef struct {
    const char *name;
    void (*run)(fuzz_data_provider *provider);
} fuzz_target;

static const fuzz_target fuzz_targets[] = {
    {"ecdsa", fuzz_ecdsa},
#ifdef ENABLE_MODULE_ECDH
    {"ecdh", fuzz_ecdh},
#endif
#ifdef ENABLE_MODULE_RECOVERY
    {"recovery", fuzz_recovery},
#endif
#ifdef ENABLE_MODULE_EXTRAKEYS
    {"extrakeys", fuzz_extrakeys},
#endif
#ifdef ENABLE_MODULE_SCHNORRSIG
    {"schnorrsig", fuzz_schnorrsig},
#endif
#ifdef ENABLE_MODULE_MUSIG
    {"musig", fuzz_musig},
#endif
#ifdef ENABLE_MODULE_ELLSWIFT
    {"ellswift", fuzz_ellswift},
#endif
#ifdef ENABLE_MODULE_SILENTPAYMENTS
    {"silentpayments", fuzz_silentpayments},
#endif
};

static const fuzz_target *fuzz_selected = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const char *name = getenv("FUZZ");
    size_t i;
    (void)argc;
    (void)argv;

    for (i = 0; i < sizeof(fuzz_targets) / sizeof(fuzz_targets[0]); i++) {
        if (name != NULL && strcmp(name, fuzz_targets[i].name) == 0) {
            fuzz_selected = &fuzz_targets[i];
        }
    }
    if (fuzz_selected == NULL) {
        fprintf(stderr, "Set FUZZ to one of these targets:\n");
        for (i = 0; i < sizeof(fuzz_targets) / sizeof(fuzz_targets[0]); i++) {
            fprintf(stderr, "%s\n", fuzz_targets[i].name);
        }
        exit(EXIT_FAILURE);
    }

    fuzz_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    CHECK(fuzz_ctx != NULL);

    /* The targets skip inputs the consume helpers reject, so check that known-valid input gets through. */
    {
        static const unsigned char g33[33] = {
            0x02, 0x79, 0xbe, 0x66, 0x7e, 0xf9, 0xdc, 0xbb, 0xac, 0x55, 0xa0, 0x62, 0x95, 0xce, 0x87, 0x0b, 0x07,
            0x02, 0x9b, 0xfc, 0xdb, 0x2d, 0xce, 0x28, 0xd9, 0x59, 0xf2, 0x81, 0x5b, 0x16, 0xf8, 0x17, 0x98
        };
        unsigned char one[32] = {0};
        fuzz_data_provider provider;
        secp256k1_pubkey pubkey, g;
        one[31] = 1;
        provider.data = one;
        provider.remaining = sizeof(one);
        CHECK(fuzz_consume_seckey(&provider) == one && provider.remaining == 0);
        provider.data = g33;
        provider.remaining = sizeof(g33);
        CHECK(fuzz_consume_pubkey(&provider, &pubkey) == 1 && provider.remaining == 0);
        CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &g, one) == 1);
        CHECK(secp256k1_ec_pubkey_cmp(fuzz_ctx, &pubkey, &g) == 0);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    static const uint8_t empty[1] = {0};
    fuzz_data_provider provider;
    /* Arithmetic on a NULL pointer is undefined, even with size 0 */
    provider.data = size ? data : empty;
    provider.remaining = size;
    fuzz_selected->run(&provider);
    return 0;
}
