#ifndef SECP256K1_DLEQ_IMPL_H
#define SECP256K1_DLEQ_IMPL_H

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0374/aux")||SHA256("BIP0374/aux"). */
static void secp256k1_nonce_function_bip374_sha256_tagged_aux(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x48479343ul;
    sha->s[1] = 0xa9eb648cul;
    sha->s[2] = 0x58952fe4ul;
    sha->s[3] = 0x4772d3b2ul;
    sha->s[4] = 0x977ab0a0ul;
    sha->s[5] = 0xcb8e2740ul;
    sha->s[6] = 0x60bb4b81ul;
    sha->s[7] = 0x68a41b66ul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0374/nonce")||SHA256("BIP0374/nonce"). */
static void secp256k1_nonce_function_bip374_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0xa810fc87ul;
    sha->s[1] = 0x3b4a4d2aul;
    sha->s[2] = 0xe302cfb4ul;
    sha->s[3] = 0x322df1a0ul;
    sha->s[4] = 0xd2e7fb82ul;
    sha->s[5] = 0x7808570dul;
    sha->s[6] = 0x9c33e0cdul;
    sha->s[7] = 0x2dfbf7f6ul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0374/challenge")||SHA256("BIP0374/challenge"). */
static void secp256k1_dleq_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x24f1c9c7ul;
    sha->s[1] = 0xd1538c75ul;
    sha->s[2] = 0xc9874ae8ul;
    sha->s[3] = 0x6566de76ul;
    sha->s[4] = 0x487843c9ul;
    sha->s[5] = 0xc13d8026ul;
    sha->s[6] = 0x39a2f3eful;
    sha->s[7] = 0x2ad0fcb3ul;

    sha->bytes = 64;
}

static int secp256k1_dleq_hash_point(secp256k1_sha256 *sha, secp256k1_ge *p) {
    unsigned char buf[33];
    size_t size = 33;
    if (!secp256k1_eckey_pubkey_serialize(p, buf, &size, 1)) {
        return 0;
    }
    secp256k1_sha256_write(sha, buf, size);
    return 1;
}

static void secp256k1_nonce_function_dleq(unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *aux_rand32, const unsigned char *m) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (aux_rand32 != NULL) {
        secp256k1_nonce_function_bip374_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(&sha, aux_rand32, 32);
        secp256k1_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    } else {
        /* Precomputed TaggedHash("BIP0374/aux", 0x0000...00); */
        static const unsigned char ZERO_MASK[32] = {
            38, 255, 199, 133, 21, 94, 75, 99,
            18, 166, 0, 53, 197, 146, 253, 84,
            197, 228, 235, 145, 124, 59, 203, 21,
            66, 88, 250, 253, 207, 123, 43, 55
        };
        for (i = 0; i < 32; i++) {
            masked_key[i] = key32[i] ^ ZERO_MASK[i];
        }
    }

    secp256k1_nonce_function_bip374_sha256_tagged(&sha);
    /* Hash masked-key||msg using the tagged hash as per the spec */
    secp256k1_sha256_write(&sha, masked_key, 32);
    secp256k1_sha256_write(&sha, msg, msglen);
    if (m != NULL) {
        secp256k1_sha256_write(&sha, m, 32);
    }
    secp256k1_sha256_finalize(&sha, nonce32);
    secp256k1_sha256_clear(&sha);
    secp256k1_memclear_explicit(masked_key, sizeof(masked_key));
}

/* Generates a nonce as defined in BIP0374 */
static int secp256k1_dleq_nonce(secp256k1_scalar *k, const unsigned char *a32, const unsigned char *A_33, const unsigned char *C_33, const unsigned char *aux_rand32, const unsigned char *m) {
    unsigned char buf[66];
    unsigned char nonce[32];

    memcpy(buf, A_33, 33);
    memcpy(buf + 33, C_33, 33);
    secp256k1_nonce_function_dleq(nonce, buf, 66, a32, aux_rand32, m);

    secp256k1_scalar_set_b32(k, nonce, NULL);
    if (secp256k1_scalar_is_zero(k)) {
        return 0;
    }

    return 1;
}

/* Generates a challenge as defined in BIP0374 */
static void secp256k1_dleq_challenge(secp256k1_scalar *e, secp256k1_ge *B, secp256k1_ge *R1, secp256k1_ge *R2, secp256k1_ge *A, secp256k1_ge *C, const unsigned char *m) {
    unsigned char buf[32];
    secp256k1_sha256 sha;
    secp256k1_ge generator_point = secp256k1_ge_const_g;

    secp256k1_dleq_sha256_tagged(&sha);
    secp256k1_dleq_hash_point(&sha, A);
    secp256k1_dleq_hash_point(&sha, B);
    secp256k1_dleq_hash_point(&sha, C);
    secp256k1_dleq_hash_point(&sha, &generator_point);
    secp256k1_dleq_hash_point(&sha, R1);
    secp256k1_dleq_hash_point(&sha, R2);
    if (m) secp256k1_sha256_write(&sha, m, 32);
    secp256k1_sha256_finalize(&sha, buf);

    secp256k1_scalar_set_b32(e, buf, NULL);
}

/* Generate points from scalar a such that A = a*G and C = a*B */
static void secp256k1_dleq_pair(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_ge *A, secp256k1_ge *C, const secp256k1_scalar *a, const secp256k1_ge *B) {
    secp256k1_gej Aj, Cj;

    secp256k1_ecmult_gen(ecmult_gen_ctx, &Aj, a);
    secp256k1_ge_set_gej(A, &Aj);
    secp256k1_ecmult_const(&Cj, B, a);
    secp256k1_ge_set_gej(C, &Cj);
}

/* DLEQ Proof Generation
 *
 * For given elliptic curve points A, B, C, and G, the prover generates a proof to prove knowledge of a scalar a such
 * that A = a⋅G and C = a⋅B without revealing anything about a.
 *
 *  Returns: 1 if proof creation was successful. 0 if an error occurred.
 *  Out:       scalar e: part of proof = bytes(32, e) || bytes(32, s).
 *             scalar s: other part of proof = bytes(32, e) || bytes(32, s).
 *  In:     a : scalar a to be proven that both A and C were generated from
 *          B : point on the curve
 *          A : point on the curve(a⋅G) generated from a
 *          C : point on the curve(a⋅B) generated from a
 * aux_rand32 : pointer to 32-byte auxiliary randomness used to generate the nonce in secp256k1_nonce_function_dleq.
 *          m : an optional message
 * */
static int secp256k1_dleq_prove(const secp256k1_context *ctx, secp256k1_scalar *s, secp256k1_scalar *e, const secp256k1_scalar *a, secp256k1_ge *B, secp256k1_ge *A, secp256k1_ge *C, const unsigned char *aux_rand32, const unsigned char *m) {
    secp256k1_ge R1, R2;
    secp256k1_scalar k = { 0 };
    unsigned char a32[32];
    unsigned char A_33[33];
    unsigned char B_33[33];
    unsigned char C_33[33];
    int ret = 1;
    size_t pubkey_size = 33;

    secp256k1_scalar_get_b32(a32, a);
    if (!secp256k1_eckey_pubkey_serialize(B, B_33, &pubkey_size, 1)) {
        return 0;
    }
    if (!secp256k1_eckey_pubkey_serialize(A, A_33, &pubkey_size, 1)) {
        return 0;
    }
    if (!secp256k1_eckey_pubkey_serialize(C, C_33, &pubkey_size, 1)) {
        return 0;
    }
    ret &= secp256k1_dleq_nonce(&k, a32, A_33, C_33, aux_rand32, m);

    /* R1 = k*G, R2 = k*B */
    secp256k1_dleq_pair(&ctx->ecmult_gen_ctx, &R1, &R2, &k, B);
    /* We declassify the non-secret values R1 and R2 to allow using them as
     * branch points. */
    secp256k1_declassify(ctx, &R1, sizeof(R1));
    secp256k1_declassify(ctx, &R2, sizeof(R2));

    /* e = tagged hash(A, B, C, R1, R2) */
    /* s = k + e * a */
    secp256k1_dleq_challenge(e, B, &R1, &R2, A, C, m);
    secp256k1_scalar_mul(s, e, a);
    secp256k1_scalar_add(s, s, &k);

    secp256k1_scalar_clear(&k);
    secp256k1_memclear_explicit(a32, sizeof(a32));
    return ret;
}

/* DLEQ Proof Verification
 *
 * Verifies the proof. If the following algorithm succeeds, the points A and C were both generated from the same scalar.
 * The former from multiplying by G, and the latter from multiplying by B.
 *
 *  Returns: 1 if proof verification was successful. 0 if an error occurred.
 *  In: proof : proof bytes(32, e) || bytes(32, s) consists of scalar e and scalar s
 *          A : point on the curve(a⋅G) computed from a
 *          B : point on the curve
 *          C : point on the curve(a⋅B) computed from a
 *          m : optional message
 * */
static int secp256k1_dleq_verify(secp256k1_scalar *s, secp256k1_scalar *e, secp256k1_ge *A, secp256k1_ge *B, secp256k1_ge *C, const unsigned char *m) {
    secp256k1_scalar e_neg;
    secp256k1_scalar e_expected;
    secp256k1_gej Bj;
    secp256k1_gej Aj, Cj;
    secp256k1_gej R1j, R2j;
    secp256k1_ge R1, R2;
    secp256k1_gej tmpj;

    secp256k1_gej_set_ge(&Aj, A);
    secp256k1_gej_set_ge(&Cj, C);

    secp256k1_scalar_negate(&e_neg, e);
    /* R1 = s*G  - e*A */
    secp256k1_ecmult(&R1j, &Aj, &e_neg, s);
    /* R2 = s*B - e*C */
    secp256k1_ecmult(&tmpj, &Cj, &e_neg, &secp256k1_scalar_zero);
    secp256k1_gej_set_ge(&Bj, B);
    secp256k1_ecmult(&R2j, &Bj, s, &secp256k1_scalar_zero);
    secp256k1_gej_add_var(&R2j, &R2j, &tmpj, NULL);

    secp256k1_ge_set_gej(&R1, &R1j);
    secp256k1_ge_set_gej(&R2, &R2j);
    secp256k1_dleq_challenge(&e_expected, B, &R1, &R2, A, C, m);

    secp256k1_scalar_add(&e_expected, &e_expected, &e_neg);
    return secp256k1_scalar_is_zero(&e_expected);
}

#endif
