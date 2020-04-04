#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H

#include "include/secp256k1_ecdsa_adaptor.h"

/* struct agent { */
/*     secp256k1_pubkey left_lock; */
/*     secp256k1_pubkey right_lock; */
/*     /\* adaptor secret for right_lock - left_lock *\/ */
/*     unsigned char adaptor_secret[32]; */
/*     secp256k1_pubkey pubkey; */
/*     unsigned char secret[32]; */
/* }; */

/* void multi_hop_lock_test(void) { */
/*     /\* TODO: initialize *\/ */
/*     struct agent Sender; */
/*     struct agent Intermediate; */
/*     struct agent Receiver; */

/*     /\* TODO everything *\/ */
/* } */


void rand_scalar(secp256k1_scalar *scalar) {
    unsigned char buf32[32];
    secp256k1_rand256(buf32);
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
    unsigned char algo16[16] = { 0 };
    secp256k1_scalar sk;
    secp256k1_ge gen2;
    secp256k1_ge p1, p2;

    rand_point(&gen2);
    rand_scalar(&sk);
    CHECK(secp256k1_dleq_proof(&ctx->ecmult_gen_ctx, &s, &e, algo16, &sk, &gen2) == 1);
    secp256k1_dleq_pair(&ctx->ecmult_gen_ctx, &p1, &p2, &sk, &gen2);
    CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &e, &p1, &gen2, &p2) == 1);

    {
        unsigned char algo16_tmp[16] = { 1 };
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo16_tmp, &s, &e, &p1, &gen2, &p2) == 0);
    }
    {
        secp256k1_scalar tmp;
        secp256k1_scalar_set_int(&tmp, 1);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo16, &tmp, &e, &p1, &gen2, &p2) == 0);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &tmp, &p1, &gen2, &p2) == 0);
    }
    {
        secp256k1_ge p_tmp;
        rand_point(&p_tmp);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &e, &p_tmp, &gen2, &p2) == 0);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &e, &p1, &p_tmp, &p2) == 0);
        CHECK(secp256k1_dleq_verify(&ctx->ecmult_ctx, algo16, &s, &e, &p1, &gen2, &p_tmp) == 0);
    }
}


void adaptor_tests(void) {
    unsigned char adaptor_sig[65];
    unsigned char adaptor_proof[97];
    unsigned char seckey[32];
    unsigned char msg[32];
    unsigned char adaptor_secret[32];
    secp256k1_pubkey adaptor;

    secp256k1_rand256(seckey);
    secp256k1_rand256(msg);
    secp256k1_rand256(adaptor_secret);

    CHECK(secp256k1_ec_pubkey_create(ctx, &adaptor, adaptor_secret) == 1);
    CHECK(secp256k1_ecdsa_adaptor_sign(ctx, adaptor_sig, adaptor_proof, seckey, &adaptor, msg) == 1);
}

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


