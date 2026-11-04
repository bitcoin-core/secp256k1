/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ELLSWIFT_FUZZ_H
#define SECP256K1_MODULE_ELLSWIFT_FUZZ_H

#include "../../../include/secp256k1_ellswift.h"

static int fuzz_ellswift_copy_x(unsigned char *output, const unsigned char *x32, const unsigned char *ell_a64, const unsigned char *ell_b64, void *data) {
    (void)ell_a64;
    (void)ell_b64;
    (void)data;
    memcpy(output, x32, 32);
    return 1;
}

static void fuzz_ellswift(fuzz_data_provider *provider) {
    /* decode(encode(pubkey)) == pubkey */
    {
        secp256k1_pubkey pubkey, decoded;
        int have_pubkey = fuzz_consume_pubkey(provider, &pubkey);
        const unsigned char *rnd32 = fuzz_consume_bytes(provider, 32);
        if (have_pubkey && rnd32) {
            unsigned char ell64[64];
            CHECK(secp256k1_ellswift_encode(fuzz_ctx, ell64, &pubkey, rnd32) == 1);
            CHECK(secp256k1_ellswift_decode(fuzz_ctx, &decoded, ell64) == 1);
            CHECK(secp256k1_memcmp_var(&pubkey, &decoded, sizeof(pubkey)) == 0);
        }
    }
    /* Every 64-byte string decodes, to a key that re-parses */
    {
        const unsigned char *ell64 = fuzz_consume_bytes(provider, 64);
        if (ell64) {
            secp256k1_pubkey decoded, parsed;
            unsigned char ser[33];
            size_t n = sizeof(ser);
            CHECK(secp256k1_ellswift_decode(fuzz_ctx, &decoded, ell64) == 1);
            CHECK(secp256k1_ec_pubkey_serialize(fuzz_ctx, ser, &n, &decoded, SECP256K1_EC_COMPRESSED) == 1);
            CHECK(secp256k1_ec_pubkey_parse(fuzz_ctx, &parsed, ser, n) == 1);
            CHECK(secp256k1_memcmp_var(&decoded, &parsed, sizeof(decoded)) == 0);
        }
    }
    /* ellswift_create decodes to ec_pubkey_create's key, and both parties of xdh agree */
    {
        const unsigned char *seckey_a = fuzz_consume_seckey(provider);
        const unsigned char *seckey_b = fuzz_consume_seckey(provider);
        if (seckey_a && seckey_b) {
            /* NULL when fewer than 32 bytes remain */
            const unsigned char *auxrnd32 = fuzz_consume_bytes(provider, 32);
            unsigned char ell_a64[64], ell_b64[64], secret_a[32], secret_b[32];
            secp256k1_pubkey pubkey, decoded;

            CHECK(secp256k1_ellswift_create(fuzz_ctx, ell_a64, seckey_a, auxrnd32) == 1);
            CHECK(secp256k1_ellswift_create(fuzz_ctx, ell_b64, seckey_b, NULL) == 1);
            CHECK(secp256k1_ellswift_decode(fuzz_ctx, &decoded, ell_a64) == 1);
            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &pubkey, seckey_a) == 1);
            CHECK(secp256k1_memcmp_var(&pubkey, &decoded, sizeof(pubkey)) == 0);

            CHECK(secp256k1_ellswift_xdh(fuzz_ctx, secret_a, ell_a64, ell_b64, seckey_a, 0, secp256k1_ellswift_xdh_hash_function_bip324, NULL) == 1);
            CHECK(secp256k1_ellswift_xdh(fuzz_ctx, secret_b, ell_a64, ell_b64, seckey_b, 1, secp256k1_ellswift_xdh_hash_function_bip324, NULL) == 1);
            CHECK(secp256k1_memcmp_var(secret_a, secret_b, sizeof(secret_a)) == 0);
        }
    }
    /* Against a peer's arbitrary 64 bytes, the shared x is the x of seckey * decode(peer) */
    {
        const unsigned char *seckey = fuzz_consume_seckey(provider);
        const unsigned char *peer64 = fuzz_consume_bytes(provider, 64);
        if (seckey && peer64) {
            unsigned char ours64[64], x32[32], ser[33];
            size_t n = sizeof(ser);
            secp256k1_pubkey peer;

            CHECK(secp256k1_ellswift_create(fuzz_ctx, ours64, seckey, NULL) == 1);
            CHECK(secp256k1_ellswift_xdh(fuzz_ctx, x32, ours64, peer64, seckey, 0, fuzz_ellswift_copy_x, NULL) == 1);
            CHECK(secp256k1_ellswift_decode(fuzz_ctx, &peer, peer64) == 1);
            CHECK(secp256k1_ec_pubkey_tweak_mul(fuzz_ctx, &peer, seckey) == 1);
            CHECK(secp256k1_ec_pubkey_serialize(fuzz_ctx, ser, &n, &peer, SECP256K1_EC_COMPRESSED) == 1);
            CHECK(secp256k1_memcmp_var(x32, ser + 1, 32) == 0);
        }
    }
}

#endif /* SECP256K1_MODULE_ELLSWIFT_FUZZ_H */
