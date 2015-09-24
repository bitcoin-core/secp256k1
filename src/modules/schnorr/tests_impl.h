/**********************************************************************
 * Copyright (c) 2014-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORR_TESTS
#define SECP256K1_MODULE_SCHNORR_TESTS

#include "include/secp256k1_schnorr.h"

void test_schnorr_end_to_end(void) {
    unsigned char privkey[32];
    unsigned char message[32];
    unsigned char schnorr_signature[64];
    secp256k1_pubkey pubkey, recpubkey;

    /* Generate a random key and message. */
    {
        secp256k1_scalar key;
        random_scalar_order_test(&key);
        secp256k1_scalar_get_b32(privkey, &key);
        secp256k1_rand256_test(message);
    }

    /* Construct and verify corresponding public key. */
    CHECK(secp256k1_ec_seckey_verify(ctx, privkey) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, privkey) == 1);

    /* Schnorr sign. */
    CHECK(secp256k1_schnorr_sign(ctx, schnorr_signature, message, privkey, NULL, NULL) == 1);
    CHECK(secp256k1_schnorr_verify(ctx, schnorr_signature, message, &pubkey) == 1);
    CHECK(secp256k1_schnorr_recover(ctx, &recpubkey, schnorr_signature, message) == 1);
    CHECK(memcmp(&pubkey, &recpubkey, sizeof(pubkey)) == 0);
    /* Destroy signature and verify again. */
    schnorr_signature[secp256k1_rand32() % 64] += 1 + (secp256k1_rand32() % 255);
    CHECK(secp256k1_schnorr_verify(ctx, schnorr_signature, message, &pubkey) == 0);
    CHECK(secp256k1_schnorr_recover(ctx, &recpubkey, schnorr_signature, message) != 1 ||
          memcmp(&pubkey, &recpubkey, sizeof(pubkey)) != 0);
}

/** Horribly broken hash function. Do not use for anything but tests. */
void test_schnorr_hash(unsigned char *h32, const unsigned char *r32, const unsigned char *msg32) {
    int i;
    for (i = 0; i < 32; i++) {
        h32[i] = r32[i] ^ msg32[i];
    }
}

void test_schnorr_sign_verify(void) {
    unsigned char msg32[32];
    unsigned char sig64[3][64];
    secp256k1_gej pubkeyj[3];
    secp256k1_ge pubkey[3];
    secp256k1_scalar key[3];
    int i = 0;
    int k;

    secp256k1_rand256_test(msg32);

    for (k = 0; k < 3; k++) {
        random_scalar_order_test(&key[k]);

        do {
            unsigned char nonce32[32];
            secp256k1_ge pubnonce;
            secp256k1_scalar privnonce;
            secp256k1_rand256_test(nonce32);
            if (secp256k1_schnorr_nonces_set_b32(&ctx->ecmult_gen_ctx, &privnonce, &pubnonce, nonce32, NULL) && secp256k1_schnorr_sig_sign(sig64[k], &key[k], &privnonce, &pubnonce, &test_schnorr_hash, msg32)) {
                break;
            }
        } while(1);

        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubkeyj[k], &key[k]);
        secp256k1_ge_set_gej_var(&pubkey[k], &pubkeyj[k]);
        CHECK(secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64[k], &pubkey[k], &test_schnorr_hash, msg32));

        for (i = 0; i < 4; i++) {
            int pos = secp256k1_rand32() % 64;
            int mod = 1 + (secp256k1_rand32() % 255);
            sig64[k][pos] ^= mod;
            CHECK(secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64[k], &pubkey[k], &test_schnorr_hash, msg32) == 0);
            sig64[k][pos] ^= mod;
        }
    }
}

void test_schnorr_multisign(void) {
    unsigned char msg[32];
    unsigned char sec[5][32];
    secp256k1_pubkey pub[5];
    unsigned char stage1[5][96];
    unsigned char stage2[5][64];
    unsigned char allsig[64];
    unsigned char allsig1[64];
    const secp256k1_pubkey *allpubs[5];
    const unsigned char *allstage2s[5];
    secp256k1_pubkey allpub;
    int n, i;
    int damage;
    int ret = 0;

    n = 1 + (secp256k1_rand32() % 5);
    if (n == 1) {
        damage = (secp256k1_rand32() % 2) ? (2 + (secp256k1_rand32() % 3)) : 0;
    } else {
        damage = (secp256k1_rand32() % 2) ? (1 + (secp256k1_rand32() % 4)) : 0;
    }
    secp256k1_rand256_test(msg);
    for (i = 0; i < n; i++) {
        do {
            secp256k1_rand256_test(sec[i]);
        } while (!secp256k1_ec_seckey_verify(ctx, sec[i]));
        CHECK(secp256k1_ec_pubkey_create(ctx, &pub[i], sec[i]));
        CHECK(secp256k1_schnorr_multisign_stage1(ctx, stage1[i], msg, sec[i], NULL, NULL));
        CHECK(secp256k1_schnorr_sign(ctx, allsig1, msg, sec[i], NULL, NULL));
        CHECK(memcmp(stage1[i], allsig1, 32) == 0);
        allpubs[i] = &pub[i];
    }
    if (damage == 1) {
        stage1[secp256k1_rand32() % (n - 1)][secp256k1_rand32() % 97] ^= 1 + (secp256k1_rand32() % 255);
    } else if (damage == 2) {
        sec[secp256k1_rand32() % n][secp256k1_rand32() % 32] ^= 1 + (secp256k1_rand32() % 255);
    }
    for (i = 0; i < n; i++) {
        const unsigned char *stage1s[4];
        const secp256k1_pubkey *pubs[4];
        int j;
        for (j = 0; j < i; j++) {
            stage1s[j] = stage1[j];
            pubs[j] = &pub[j];
        }
        for (j = i + 1; j < n; j++) {
            stage1s[j - 1] = stage1[j];
            pubs[j - 1] = &pub[j];
        }
        ret |= (secp256k1_schnorr_multisign_stage2(ctx, stage2[i], stage1s, n - 1, msg, pubs, sec[i], NULL, NULL) != 1) * 1;
        allstage2s[i] = stage2[i];
    }
    if (damage == 3) {
        stage2[secp256k1_rand32() % n][secp256k1_rand32() % 64] ^= 1 + (secp256k1_rand32() % 255);
    }
    ret |= (secp256k1_ec_pubkey_combine(ctx, &allpub, allpubs, n) != 1) * 2;
    if ((ret & 1) == 0) {
        ret |= (secp256k1_schnorr_multisign_combine(ctx, allsig, allstage2s, n) != 1) * 4;
    }
    if (damage == 4) {
        allsig[secp256k1_rand32() % 64] ^= 1 + (secp256k1_rand32() % 255);
    }
    if ((ret & 7) == 0) {
        ret |= (secp256k1_schnorr_verify(ctx, allsig, msg, &allpub) != 1) * 8;
    }
    if (n == 1 && (ret == 0)) {
        ret |= (secp256k1_schnorr_sign(ctx, allsig1, msg, sec[0], NULL, NULL) != 1) * 16;
        ret |= (memcmp(allsig1, allsig, 64) != 0) * 32;
    }
    CHECK((ret == 0) == (damage == 0));
}

void test_schnorr_recovery(void) {
    unsigned char msg32[32];
    unsigned char sig64[64];
    secp256k1_ge Q;

    secp256k1_rand256_test(msg32);
    secp256k1_rand256_test(sig64);
    secp256k1_rand256_test(sig64 + 32);
    if (secp256k1_schnorr_sig_recover(&ctx->ecmult_ctx, sig64, &Q, &test_schnorr_hash, msg32) == 1) {
        CHECK(secp256k1_schnorr_sig_verify(&ctx->ecmult_ctx, sig64, &Q, &test_schnorr_hash, msg32) == 1);
    }
}

void run_schnorr_tests(void) {
    int i;
    for (i = 0; i < 32*count; i++) {
        test_schnorr_end_to_end();
    }
    for (i = 0; i < 32 * count; i++) {
         test_schnorr_sign_verify();
    }
    for (i = 0; i < 16 * count; i++) {
         test_schnorr_recovery();
    }
    for (i = 0; i < 10 * count; i++) {
         test_schnorr_multisign();
    }
}

#endif
