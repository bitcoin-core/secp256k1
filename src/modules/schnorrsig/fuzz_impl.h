/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_FUZZ_H
#define SECP256K1_MODULE_SCHNORRSIG_FUZZ_H

#include "../../../include/secp256k1_schnorrsig.h"

static void fuzz_schnorrsig(fuzz_data_provider *provider) {
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pubkey;
    unsigned char sig[64], sig2[64];
    const unsigned char *seckey, *msg32, *aux_rand32, *len, *msg, *flip;
    static const unsigned char zeros32[32] = {0};

    seckey = fuzz_consume_seckey(provider);
    msg32 = fuzz_consume_bytes(provider, 32);
    if (!seckey || !msg32) {
        return;
    }
    /* NULL when fewer than 32 bytes remain */
    aux_rand32 = fuzz_consume_bytes(provider, 32);
    CHECK(secp256k1_keypair_create(fuzz_ctx, &keypair, seckey) == 1);
    CHECK(secp256k1_keypair_xonly_pub(fuzz_ctx, &pubkey, NULL, &keypair) == 1);

    /* Sign & verify */
    CHECK(secp256k1_schnorrsig_sign32(fuzz_ctx, sig, msg32, &keypair, aux_rand32) == 1);
    CHECK(secp256k1_schnorrsig_verify(fuzz_ctx, sig, msg32, 32, &pubkey) == 1);

    /* sign_custom with msglen 32 and ndata = aux_rand32 is sign32 */
    {
        secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
        extraparams.ndata = (void *)aux_rand32;
        CHECK(secp256k1_schnorrsig_sign_custom(fuzz_ctx, sig2, msg32, 32, &keypair, &extraparams) == 1);
        CHECK(secp256k1_memcmp_var(sig, sig2, sizeof(sig)) == 0);
    }
    /* A NULL aux_rand32 is treated as all-zero */
    if (aux_rand32 == NULL) {
        CHECK(secp256k1_schnorrsig_sign32(fuzz_ctx, sig2, msg32, &keypair, zeros32) == 1);
        CHECK(secp256k1_memcmp_var(sig, sig2, sizeof(sig)) == 0);
    }
    /* Sign & verify a message of consumed length */
    len = fuzz_consume_bytes(provider, 1);
    msg = len ? fuzz_consume_bytes(provider, *len) : NULL;
    if (msg) {
        CHECK(secp256k1_schnorrsig_sign_custom(fuzz_ctx, sig, msg, *len, &keypair, NULL) == 1);
        CHECK(secp256k1_schnorrsig_verify(fuzz_ctx, sig, msg, *len, &pubkey) == 1);
        /* A signature with one bit flipped does not verify */
        flip = fuzz_consume_bytes(provider, 2);
        if (flip) {
            sig[flip[0] % 64] ^= 1 << (flip[1] % 8);
            CHECK(secp256k1_schnorrsig_verify(fuzz_ctx, sig, msg, *len, &pubkey) == 0);
        }
    }
    /* No one knows the secret key of this x coordinate, so no one can sign for it. */
    {
        const unsigned char *garbage = fuzz_consume_bytes(provider, 64);
        if (garbage) {
            static const unsigned char fixed_msg[33] = "This is the super secret message";
            static const unsigned char fixed_pubkey[33] = "A public key without private key";
            CHECK(secp256k1_xonly_pubkey_parse(fuzz_ctx, &pubkey, fixed_pubkey) == 1);
            CHECK(secp256k1_schnorrsig_verify(fuzz_ctx, garbage, fixed_msg, 32, &pubkey) == 0);
        }
    }
}

#endif /* SECP256K1_MODULE_SCHNORRSIG_FUZZ_H */
