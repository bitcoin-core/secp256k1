#ifndef _SECP256K1_DLEQ_IMPL_H_
#define _SECP256K1_DLEQ_IMPL_H_

/* TODO: it's not bip340, it's modified */
static int nonce_function_bip340(unsigned char *nonce32, const unsigned char *msg32, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo16, void *data, unsigned int counter) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];

    if (counter != 0) {
        return 0;
    }
    if (algo16 == NULL) {
        return 0;
    }

    if (data != NULL) {
        return 0;
    }

    secp256k1_sha256_initialize_tagged(&sha, algo16, 16);

    /* Hash (masked-)key||pk||msg using the tagged hash as per the spec */
    if (data != NULL) {
        secp256k1_sha256_write(&sha, masked_key, 32);
    } else {
        secp256k1_sha256_write(&sha, key32, 32);
    }
    secp256k1_sha256_write(&sha, xonly_pk32, 32);
    secp256k1_sha256_write(&sha, msg32, 32);
    secp256k1_sha256_finalize(&sha, nonce32);
    return 1;
}

static void secp256k1_dleq_serialize_point(unsigned char *buf33, const secp256k1_ge *p) {
    secp256k1_fe x = p->x;
    secp256k1_fe y = p->y;

    secp256k1_fe_normalize(&y);
    buf33[0] = secp256k1_fe_is_odd(&y);
    secp256k1_fe_normalize(&x);
    secp256k1_fe_get_b32(&buf33[1], &x);
}

/* TODO: remove */
static void print_buf(const unsigned char *buf, size_t n) {
    size_t i;
    for (i = 0; i < n; i++) {
        printf("%02X", buf[i]);
    }
    printf("\n");
}
static void print_scalar(const secp256k1_scalar *x) {
    unsigned char buf32[32];
    secp256k1_scalar_get_b32(buf32, x);
    print_buf(buf32, 32);
}

static void print_ge(const secp256k1_ge *p) {
    unsigned char buf33[33];
    secp256k1_dleq_serialize_point(buf33, p);
    print_buf(buf33, 33);
}

static void secp256k1_dleq_hash_point(secp256k1_sha256 *sha, const secp256k1_ge *p) {
    unsigned char buf33[33];
    secp256k1_dleq_serialize_point(buf33, p);
    secp256k1_sha256_write(sha, buf33, 33);
}

static void secp256k1_dleq_challenge_hash(secp256k1_scalar *e, const unsigned char *algo16, const secp256k1_ge *r1, const secp256k1_ge *r2, const secp256k1_ge *p1, const secp256k1_ge *p2) {
    secp256k1_sha256 sha;
    unsigned char buf32[32];

    /* TODO: use tagged hash function */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, algo16, 16);
    secp256k1_dleq_hash_point(&sha, r1);
    secp256k1_dleq_hash_point(&sha, r2);
    secp256k1_dleq_hash_point(&sha, p1);
    secp256k1_dleq_hash_point(&sha, p2);
    secp256k1_sha256_finalize(&sha, buf32);

    secp256k1_scalar_set_b32(e, buf32, NULL);
}

/* p1 = x*G, p2 = x*gen2, constant time */
static void secp256k1_dleq_pair(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_ge *p1, secp256k1_ge *p2, const secp256k1_scalar *sk, const secp256k1_ge *gen2) {
    secp256k1_gej p1j, p2j;
    secp256k1_ecmult_gen(ecmult_gen_ctx, &p1j, sk);
    secp256k1_ge_set_gej(p1, &p1j);
    secp256k1_ecmult_const(&p2j, gen2, sk, 256);
    secp256k1_ge_set_gej(p2, &p2j);
}

static int secp256k1_dleq_proof(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_scalar *s, secp256k1_scalar *e, const unsigned char *algo16, const secp256k1_scalar *sk, const secp256k1_ge *gen2) {
    unsigned char nonce32[32];
    unsigned char key32[32];
    secp256k1_ge p1, p2;
    secp256k1_sha256 sha;
    secp256k1_gej r1j, r2j;
    secp256k1_ge r1, r2;
    unsigned char buf32[32];
    secp256k1_scalar k;

    secp256k1_dleq_pair(ecmult_gen_ctx, &p1, &p2, sk, gen2);

    secp256k1_sha256_initialize(&sha);
    secp256k1_dleq_hash_point(&sha, &p1);
    secp256k1_dleq_hash_point(&sha, &p2);
    secp256k1_sha256_finalize(&sha, buf32);

    /* everything that goes into the challenge hash must go into the nonce as well... */
    if (!nonce_function_bip340(nonce32, buf32, key32, buf32, algo16, NULL, 0)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&k, nonce32, NULL);
    if (secp256k1_scalar_is_zero(&k)) {
        return 0;
    }

    secp256k1_ecmult_gen(ecmult_gen_ctx, &r1j, &k);
    secp256k1_ge_set_gej(&r1, &r1j);
    secp256k1_ecmult_const(&r2j, gen2, &k, 256);
    secp256k1_ge_set_gej(&r2, &r2j);

    secp256k1_dleq_challenge_hash(e, algo16, &r1, &r2, &p1, &p2);
    secp256k1_scalar_mul(s, e, sk);
    secp256k1_scalar_add(s, s, &k);

    secp256k1_scalar_clear(&k);
    return 1;
}

static int secp256k1_dleq_verify(const secp256k1_ecmult_context *ecmult_ctx, const unsigned char *algo16, const secp256k1_scalar *s, const secp256k1_scalar *e, const secp256k1_ge *p1, const secp256k1_ge *gen2, const secp256k1_ge *p2) {
    secp256k1_scalar e_neg;
    secp256k1_scalar e_expected;
    secp256k1_gej gen2j;
    secp256k1_gej p1j, p2j;
    secp256k1_gej r1j, r2j;
    secp256k1_ge r1, r2;
    secp256k1_gej tmpj;

    secp256k1_gej_set_ge(&p1j, p1);
    secp256k1_gej_set_ge(&p2j, p2);

    secp256k1_scalar_negate(&e_neg, e);
    /* R1 = s*G  - e*P1 */
    secp256k1_ecmult(ecmult_ctx, &r1j, &p1j, &e_neg, s);
    /* R2 = s*gen2 - e*P2 */
    secp256k1_ecmult(ecmult_ctx, &tmpj, &p2j, &e_neg, &secp256k1_scalar_zero);
    secp256k1_gej_set_ge(&gen2j, gen2);
    secp256k1_ecmult(ecmult_ctx, &r2j, &gen2j, s, &secp256k1_scalar_zero);
    secp256k1_gej_add_var(&r2j, &r2j, &tmpj, NULL);

    secp256k1_ge_set_gej(&r1, &r1j);
    secp256k1_ge_set_gej(&r2, &r2j);
    secp256k1_dleq_challenge_hash(&e_expected, algo16, &r1, &r2, p1, p2);

    secp256k1_scalar_add(&e_expected, &e_expected, &e_neg);
    return secp256k1_scalar_is_zero(&e_expected);
}

#endif /* _SECP256K1_DLEQ_IMPL_H_ */
