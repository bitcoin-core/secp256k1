#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H

#include "include/secp256k1_ecdsa_adaptor.h"

void rand_scalar(secp256k1_scalar *scalar) {
    unsigned char buf32[32];
    secp256k1_testrand256(buf32);
    secp256k1_scalar_set_b32(scalar, buf32, NULL);
}

void rand_point(secp256k1_ge *point) {
    secp256k1_scalar x;
    secp256k1_gej pointj;
    rand_scalar(&x);

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pointj, &x);
    secp256k1_ge_set_gej(point, &pointj);
}

void dleq_tests(void) {
    secp256k1_scalar s, e;
    unsigned char algo33[33] = { 0 };
    secp256k1_scalar sk;
    secp256k1_ge gen2;
    secp256k1_ge p1, p2;

    rand_point(&gen2);
    rand_scalar(&sk);
    CHECK(secp256k1_dleq_proof(&ctx->ecmult_gen_ctx, &s, &e, algo33, &sk, &gen2) == 1);
    secp256k1_dleq_pair(&ctx->ecmult_gen_ctx, &p1, &p2, &sk, &gen2);
    CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo33, &s, &e, &p1, &gen2, &p2) == 1);

    {
        unsigned char algo33_tmp[33] = { 1 };
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo33_tmp, &s, &e, &p1, &gen2, &p2) == 0);
    }
    {
        secp256k1_scalar tmp;
        secp256k1_scalar_set_int(&tmp, 1);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo33, &tmp, &e, &p1, &gen2, &p2) == 0);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo33, &s, &tmp, &p1, &gen2, &p2) == 0);
    }
    {
        secp256k1_ge p_tmp;
        rand_point(&p_tmp);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo33, &s, &e, &p_tmp, &gen2, &p2) == 0);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo33, &s, &e, &p1, &p_tmp, &p2) == 0);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo33, &s, &e, &p1, &gen2, &p_tmp) == 0);
    }
}

void rand_flip_bit(unsigned char *array, size_t n) {
    array[secp256k1_testrand_int(n)] ^= 1 << secp256k1_testrand_int(8);
}


void test_spec_vectors(void) {
    /* Test vector 0 */
    const unsigned char adaptor_sig[162] = {
        0x03, 0x6c, 0x2f, 0x34, 0x83, 0x39, 0x42, 0xe6,
        0xee, 0xbb, 0x9e, 0x01, 0xb7, 0x1c, 0x1d, 0x5f,
        0x6e, 0xa1, 0x85, 0xe7, 0xaf, 0x60, 0x78, 0x05,
        0xab, 0x5a, 0x39, 0xa8, 0x29, 0xad, 0x7a, 0x30,
        0x40, 0x02, 0x20, 0xf5, 0x7f, 0x81, 0x2e, 0x04,
        0x3e, 0x0f, 0x5b, 0x5c, 0x8c, 0x22, 0xa5, 0xc6,
        0xef, 0xe6, 0xf7, 0x6c, 0xda, 0xa7, 0x14, 0x90,
        0xf7, 0xb3, 0xa3, 0xad, 0xb7, 0xa3, 0x91, 0x01,
        0xbf, 0x7a, 0xd4, 0xee, 0x4d, 0x04, 0x9e, 0x57,
        0x3a, 0xde, 0xe6, 0x64, 0x7a, 0xb7, 0xd9, 0x74,
        0x45, 0xd8, 0x7c, 0x42, 0x52, 0xd9, 0x1a, 0x62,
        0x79, 0x35, 0x26, 0x9e, 0x99, 0x70, 0x3a, 0x7d,
        0x41, 0x61, 0xa5, 0xb4, 0xe2, 0x67, 0x5d, 0x09,
        0xe0, 0xda, 0x65, 0xde, 0xb2, 0xed, 0x62, 0x10,
        0xe5, 0xe9, 0x92, 0x44, 0x15, 0x3e, 0x96, 0x00,
        0xed, 0x17, 0xd9, 0x0f, 0x6f, 0x31, 0x85, 0x3e,
        0x2c, 0x5f, 0xf8, 0x68, 0x0a, 0xdc, 0xbd, 0x13,
        0x93, 0xd1, 0xae, 0x8e, 0xed, 0x5c, 0xd8, 0xa8,
        0xe3, 0x96, 0x27, 0x5b, 0xe9, 0x55, 0x06, 0xbf,
        0x40, 0xa2, 0x0a, 0xc2, 0x2f, 0x66, 0xca, 0x87,
        0x5b, 0xf4
    };
    const unsigned char msg[32] = {
        0x81, 0x31, 0xe6, 0xf4, 0xb4, 0x57, 0x54, 0xf2,
        0xc9, 0x0b, 0xd0, 0x66, 0x88, 0xce, 0xea, 0xbc,
        0x0c, 0x45, 0x05, 0x54, 0x60, 0x72, 0x99, 0x28,
        0xb4, 0xee, 0xcf, 0x11, 0x02, 0x6a, 0x9e, 0x2d
    };
    const unsigned char pubkey_hex[33] = {
        0x03, 0x9b, 0x83, 0x27, 0xd9, 0x29, 0xa0, 0xe4,
        0x52, 0x85, 0xc0, 0x4d, 0x19, 0xc9, 0xff, 0xfb,
        0xee, 0x06, 0x5c, 0x26, 0x6b, 0x70, 0x19, 0x72,
        0x92, 0x2d, 0x80, 0x72, 0x28, 0x12, 0x0e, 0x43,
        0xf3
    };
    const unsigned char encryption_key_hex[33] = {
        0x03, 0x96, 0x10, 0xff, 0xb4, 0x9f, 0x92, 0x77,
        0x93, 0x69, 0x50, 0x98, 0x1d, 0x7f, 0x70, 0x1f,
        0x4b, 0xc8, 0xc5, 0x03, 0xa8, 0x76, 0x02, 0x1e,
        0x36, 0x78, 0x5b, 0x4f, 0xc4, 0x75, 0xe7, 0x4b,
        0x23
    };
    const unsigned char decryption_key_hex[32] = {
        0xda, 0x41, 0x59, 0x7c, 0x51, 0x57, 0x48, 0x8d,
        0x77, 0x24, 0xe0, 0x3f, 0xb8, 0xd8, 0x4a, 0x37,
        0x6a, 0x43, 0xb8, 0xf4, 0x15, 0x18, 0xa1, 0x1c,
        0xc3, 0x87, 0xb6, 0x69, 0xb2, 0xee, 0x65, 0x86
    };
    const unsigned char signature_hex[64] = {
        0x6c, 0x2f, 0x34, 0x83, 0x39, 0x42, 0xe6, 0xee,
        0xbb, 0x9e, 0x01, 0xb7, 0x1c, 0x1d, 0x5f, 0x6e,
        0xa1, 0x85, 0xe7, 0xaf, 0x60, 0x78, 0x05, 0xab,
        0x5a, 0x39, 0xa8, 0x29, 0xad, 0x7a, 0x30, 0x40,
        0x6d, 0x3f, 0x75, 0x42, 0xdd, 0x59, 0x6d, 0x23,
        0x6b, 0x9c, 0x5a, 0x39, 0xb7, 0xf4, 0xfc, 0x35,
        0x37, 0x7c, 0xb7, 0xea, 0x30, 0x15, 0xff, 0x42,
        0x39, 0x40, 0x9f, 0xbb, 0xac, 0xd3, 0x8e, 0x83
    };

    secp256k1_ge pubkey_ge;
    secp256k1_pubkey pubkey;
    secp256k1_ge encryption_key_ge;
    secp256k1_pubkey encryption_key;
    secp256k1_ecdsa_signature sig;
    unsigned char signature[64];

    secp256k1_eckey_pubkey_parse(&encryption_key_ge, encryption_key_hex, 33);
    secp256k1_pubkey_save(&encryption_key, &encryption_key_ge);
    secp256k1_eckey_pubkey_parse(&pubkey_ge, pubkey_hex, 33);
    secp256k1_pubkey_save(&pubkey, &pubkey_ge);
    /* ecdsa_adaptor_verify */
    CHECK(secp256k1_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &pubkey, msg, &encryption_key) == 1);
    /* ecdsa_adaptor_recover */
    secp256k1_ecdsa_adaptor_adapt(ctx, &sig, decryption_key_hex, adaptor_sig);
    secp256k1_ecdsa_signature_serialize_compact(ctx, signature, &sig);
    CHECK(secp256k1_memcmp_var(signature, signature_hex, 64) == 0);
}

void adaptor_tests(void) {
    unsigned char seckey[32];
    secp256k1_pubkey pubkey;
    unsigned char msg[32];
    unsigned char adaptor_secret[32];
    secp256k1_pubkey adaptor;
    unsigned char adaptor_sig[162];
    secp256k1_ecdsa_signature sig;

    secp256k1_testrand256(seckey);
    secp256k1_testrand256(msg);
    secp256k1_testrand256(adaptor_secret);

    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, adaptor_secret) == 1);
    CHECK(secp256k1_ecdsa_adaptor_sign(ctx, adaptor_sig, seckey, &adaptor, msg) == 1);
    {
        /* Test adaptor_sig_serialize roundtrip */
        secp256k1_ge r, rp;
        secp256k1_scalar sigr;
        secp256k1_scalar sp;
        secp256k1_scalar dleq_proof_s, dleq_proof_e;
        unsigned char adaptor_sig_tmp[162];

        CHECK(secp256k1_ecdsa_adaptor_sig_deserialize(&r, &sigr, &rp, &sp, &dleq_proof_e, &dleq_proof_s, adaptor_sig) == 1);

        secp256k1_ecdsa_adaptor_sig_serialize(adaptor_sig_tmp, &r, &rp, &sp, &dleq_proof_e, &dleq_proof_s);
        CHECK(memcmp(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp)) == 0);
    }

    /* Test adaptor_sig_verify */
    CHECK(secp256k1_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &pubkey, msg, &adaptor) == 1);
    {
        unsigned char adaptor_sig_tmp[65];
        memcpy(adaptor_sig_tmp, adaptor_sig, sizeof(adaptor_sig_tmp));
        rand_flip_bit(&adaptor_sig_tmp[1], sizeof(adaptor_sig_tmp) - 1);
        CHECK(secp256k1_ecdsa_adaptor_sig_verify(ctx, adaptor_sig_tmp, &pubkey, msg, &adaptor) == 0);
    }
    CHECK(secp256k1_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &adaptor, msg, &adaptor) == 0);
    {
        unsigned char msg_tmp[32];
        memcpy(msg_tmp, msg, sizeof(msg_tmp));
        rand_flip_bit(msg_tmp, sizeof(msg_tmp));
        CHECK(secp256k1_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &pubkey, msg_tmp, &adaptor) == 0);
    }
    CHECK(secp256k1_ecdsa_adaptor_sig_verify(ctx, adaptor_sig, &pubkey, msg, &pubkey) == 0);

    /* Test adaptor_adapt */
    CHECK(secp256k1_ecdsa_adaptor_adapt(ctx, &sig, adaptor_secret, adaptor_sig) == 1);
    CHECK(secp256k1_ecdsa_verify(ctx, &sig, msg, &pubkey) == 1);

    {
        /* Test adaptor_extract_secret */
        unsigned char adaptor_secret_tmp[32];
        CHECK(secp256k1_ecdsa_adaptor_extract_secret(ctx, adaptor_secret_tmp, &sig, adaptor_sig, &adaptor) == 1);
        CHECK(memcmp(adaptor_secret, adaptor_secret_tmp, sizeof(adaptor_secret)) == 0);
    }
}

/*/\* TODO: test multi hop lock *\/ */
/* struct agent { */
/*     secp256k1_pubkey left_lock; */
/*     secp256k1_pubkey right_lock; */
/*     /\* adaptor secret for right_lock - left_lock *\/ */
/*     unsigned char adaptor_secret[32]; */
/*     secp256k1_pubkey pubkey; */
/*     unsigned char secret[32]; */
/* }; */

/* void multi_hop_lock_test(void) { */
/*     struct agent Sender; */
/*     struct agent Intermediate; */
/*     struct agent Receiver; */

/* } */

void run_ecdsa_adaptor_tests(void) {
    int i;
    for (i = 0; i < count; i++) {
        dleq_tests();
    }
    for (i = 0; i < count; i++) {
        adaptor_tests();
    }

    test_spec_vectors();
}

#endif /* SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H */
