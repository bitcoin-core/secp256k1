#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H

#include "modules/ecdsa_adaptor/main_impl.h"

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

void rand_gen(secp256k1_ge *gen2) {
    secp256k1_scalar x;
    secp256k1_gej gen2j;
    rand_scalar(&x);

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &gen2j, &x);
    secp256k1_ge_set_gej(gen2, &gen2j);
}

void dleq_tests(void) {
    secp256k1_scalar s, e;
    unsigned char algo16[16] = { 0 };
    secp256k1_scalar sk;
    secp256k1_ge gen2;
    secp256k1_ge p1, p2;

    rand_gen(&gen2);
    rand_scalar(&sk);
    CHECK(secp256k1_dleq_proof(&s, &e, algo16, &sk, &gen2) == 1);
    secp256k1_dleq_pair(&p1, &p2, &sk, &gen2);
    CHECK(secp256k1_dleq_verify(algo16, &s, &e, &p1, &gen2, &p2) == 1);

    {
        unsigned char algo16_tmp[16] = { 1 };
        CHECK(secp256k1_dleq_verify(algo16_tmp, &s, &e, &p1, &gen2, &p2) == 0);
    }
    {
        secp256k1_scalar tmp;
        secp256k1_scalar_set_int(&tmp, 1);
        CHECK(secp256k1_dleq_verify(algo16, &tmp, &e, &p1, &gen2, &p2) == 0);
        CHECK(secp256k1_dleq_verify(algo16, &s, &tmp, &p1, &gen2, &p2) == 0);
    }
    {
        secp256k1_ge p_tmp;
        rand_gen(&p_tmp);
        CHECK(secp256k1_dleq_verify(algo16, &s, &e, &p_tmp, &gen2, &p2) == 0);
        CHECK(secp256k1_dleq_verify(algo16, &s, &e, &p1, &p_tmp, &p2) == 0);
        CHECK(secp256k1_dleq_verify(algo16, &s, &e, &p1, &gen2, &p_tmp) == 0);
    }
}

void run_ecdsa_adaptor_tests(void) {
    int i;
    for (i = 0; i < count; i++) {
        dleq_tests();
    }
}

#endif /* SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H */


