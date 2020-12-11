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
}

#endif /* SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H */
