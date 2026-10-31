/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_FUZZ_H
#define SECP256K1_MODULE_SCHNORRSIG_FUZZ_H

#include "../../../include/secp256k1_schnorrsig.h"

/* A nonce function that returns a given nonce, which may be 0 or >= n, or fails */
typedef struct {
    const unsigned char *nonce32;
    int fail;
} fuzz_schnorrsig_nonce_data;

static int fuzz_schnorrsig_nonce_function(unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    const fuzz_schnorrsig_nonce_data *d = (const fuzz_schnorrsig_nonce_data *)data;
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pubkey;
    unsigned char pk32[32];
    (void)msg;
    (void)msglen;
    (void)algolen;
    /* xonly_pk32 is "the 32-byte serialized xonly pubkey corresponding to key32", and algo "will not be NULL" */
    CHECK(secp256k1_keypair_create(fuzz_ctx, &keypair, key32) == 1);
    CHECK(secp256k1_keypair_xonly_pub(fuzz_ctx, &pubkey, NULL, &keypair) == 1);
    CHECK(secp256k1_xonly_pubkey_serialize(fuzz_ctx, pk32, &pubkey) == 1);
    CHECK(secp256k1_memcmp_var(pk32, xonly_pk32, 32) == 0);
    CHECK(algo != NULL);
    if (d->fail) {
        return 0;
    }
    memcpy(nonce32, d->nonce32, 32);
    return 1;
}

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
    /* Sign with a nonce function that returns a nonce of 0, >= n or any, or fails */
    {
        const unsigned char *cfg = fuzz_consume_bytes(provider, 1);
        const unsigned char *nonce32 = fuzz_consume_bytes(provider, 32);
        if (cfg && nonce32) {
            secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
            fuzz_schnorrsig_nonce_data nonce_data;
            unsigned char nonce[32];
            int ret;
            memcpy(nonce, nonce32, sizeof(nonce));
            if ((*cfg & 3) == 1) {
                memset(nonce, 0, sizeof(nonce));
            } else if ((*cfg & 3) == 2) {
                /* Above n, whose top 16 bytes are not all 0xff */
                memset(nonce, 0xff, 16);
            }
            nonce_data.nonce32 = nonce;
            nonce_data.fail = (*cfg >> 2) & 1;
            extraparams.noncefp = fuzz_schnorrsig_nonce_function;
            extraparams.ndata = &nonce_data;
            ret = fuzz_check_bool(secp256k1_schnorrsig_sign_custom(fuzz_ctx, sig, msg32, 32, &keypair, &extraparams));
            /* A nonce function returning 0 "will cause signing to return an error" */
            if (nonce_data.fail) {
                CHECK(ret == 0);
            }
            if (ret) {
                CHECK(secp256k1_keypair_xonly_pub(fuzz_ctx, &pubkey, NULL, &keypair) == 1);
                CHECK(secp256k1_schnorrsig_verify(fuzz_ctx, sig, msg32, 32, &pubkey) == 1);
            }
        }
    }
    /* Verification fails where R = s*G - e*P is infinity, as BIP-340 requires */
    {
        const unsigned char *r32 = fuzz_consume_bytes(provider, 32);
        if (r32) {
            secp256k1_scalar d, e;
            unsigned char pk32[32];
            int parity;
            CHECK(secp256k1_keypair_xonly_pub(fuzz_ctx, &pubkey, &parity, &keypair) == 1);
            CHECK(secp256k1_xonly_pubkey_serialize(fuzz_ctx, pk32, &pubkey) == 1);
            /* Internal functions only build the signature; the public API is under test.
             * With d the secret key of P and s = e*d, R = s*G - e*P is infinity. */
            secp256k1_scalar_set_b32(&d, seckey, NULL);
            if (parity) {
                secp256k1_scalar_negate(&d, &d);
            }
            secp256k1_schnorrsig_challenge(&fuzz_ctx->hash_ctx, &e, r32, msg32, 32, pk32);
            secp256k1_scalar_mul(&e, &e, &d);
            memcpy(sig, r32, 32);
            secp256k1_scalar_get_b32(sig + 32, &e);
            CHECK(secp256k1_schnorrsig_verify(fuzz_ctx, sig, msg32, 32, &pubkey) == 0);
        }
    }
}

#endif /* SECP256K1_MODULE_SCHNORRSIG_FUZZ_H */
