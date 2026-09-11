/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_DLEQ_MAIN_H
#define SECP256K1_MODULE_DLEQ_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_dleq.h"
#include "../../hash.h"

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0374/aux")||SHA256("BIP0374/aux"). */
static void secp256k1_nonce_function_bip374_sha256_tagged_aux(secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0x48479343ul, 0xa9eb648cul, 0x58952fe4ul, 0x4772d3b2ul,
        0x977ab0a0ul, 0xcb8e2740ul, 0x60bb4b81ul, 0x68a41b66ul
    };
    secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0374/nonce")||SHA256("BIP0374/nonce"). */
static void secp256k1_nonce_function_bip374_sha256_tagged(secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0xa810fc87ul, 0x3b4a4d2aul, 0xe302cfb4ul, 0x322df1a0ul,
        0xd2e7fb82ul, 0x7808570dul, 0x9c33e0cdul, 0x2dfbf7f6ul
    };
    secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0374/challenge")||SHA256("BIP0374/challenge"). */
static void secp256k1_dleq_sha256_tagged(secp256k1_sha256 *sha) {
    static const uint32_t midstate[8] = {
        0x24f1c9c7ul, 0xd1538c75ul, 0xc9874ae8ul, 0x6566de76ul,
        0x487843c9ul, 0xc13d8026ul, 0x39a2f3eful, 0x2ad0fcb3ul
    };
    secp256k1_sha256_initialize_midstate(sha, 64, midstate);
}

static void secp256k1_dleq_hash_point(const secp256k1_hash_ctx *hash_ctx, secp256k1_sha256 *sha, secp256k1_ge *p) {
    unsigned char buf[33];
    secp256k1_ge_serialize33(p, buf);
    secp256k1_sha256_write(hash_ctx, sha, buf, 33);
}

static void secp256k1_nonce_function_dleq(const secp256k1_hash_ctx *hash_ctx, unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *aux_rand32, const unsigned char *m) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (aux_rand32 != NULL) {
        secp256k1_nonce_function_bip374_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(hash_ctx, &sha, aux_rand32, 32);
        secp256k1_sha256_finalize(hash_ctx, &sha, masked_key);
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
    /* Hash masked-key||msg||m using the tagged hash as defined in BIP0374
     * Note: msg contains the serialized points A||C (66 bytes) */
    secp256k1_sha256_write(hash_ctx, &sha, masked_key, 32);
    secp256k1_sha256_write(hash_ctx, &sha, msg, msglen);
    if (m != NULL) {
        secp256k1_sha256_write(hash_ctx, &sha, m, 32);
    }
    secp256k1_sha256_finalize(hash_ctx, &sha, nonce32);
    secp256k1_sha256_clear(&sha);
    secp256k1_memclear_explicit(masked_key, sizeof(masked_key));
}

/* Generates a nonce as defined in BIP0374 */
static int secp256k1_dleq_nonce(const secp256k1_hash_ctx *hash_ctx, secp256k1_scalar *k, const unsigned char *a32, const unsigned char *A_33, const unsigned char *C_33, const unsigned char *aux_rand32, const unsigned char *m) {
    unsigned char buf[66];
    unsigned char nonce[32];
    int ret;

    memcpy(buf, A_33, 33);
    memcpy(buf + 33, C_33, 33);
    secp256k1_nonce_function_dleq(hash_ctx, nonce, buf, 66, a32, aux_rand32, m);

    secp256k1_scalar_set_b32(k, nonce, NULL);
    ret = !secp256k1_scalar_is_zero(k);

    secp256k1_memclear_explicit(nonce, sizeof(nonce));
    return ret;
}

/* Generates a challenge as defined in BIP0374 */
static void secp256k1_dleq_challenge(const secp256k1_hash_ctx *hash_ctx, secp256k1_scalar *e, secp256k1_ge *A, secp256k1_ge *B, secp256k1_ge *C, secp256k1_ge *R1, secp256k1_ge *R2, const unsigned char *m) {
    unsigned char buf[32];
    secp256k1_sha256 sha;
    secp256k1_ge generator_point = secp256k1_ge_const_g;

    secp256k1_dleq_sha256_tagged(&sha);
    secp256k1_dleq_hash_point(hash_ctx, &sha, A);
    secp256k1_dleq_hash_point(hash_ctx, &sha, B);
    secp256k1_dleq_hash_point(hash_ctx, &sha, C);
    secp256k1_dleq_hash_point(hash_ctx, &sha, &generator_point);
    secp256k1_dleq_hash_point(hash_ctx, &sha, R1);
    secp256k1_dleq_hash_point(hash_ctx, &sha, R2);
    if (m) secp256k1_sha256_write(hash_ctx, &sha, m, 32);
    secp256k1_sha256_finalize(hash_ctx, &sha, buf);

    secp256k1_scalar_set_b32(e, buf, NULL);
}

/* Generate points from scalar a such that A = a*G and C = a*B */
static void secp256k1_dleq_pair(const secp256k1_ecmult_gen_context *ecmult_gen_ctx, secp256k1_ge *A, secp256k1_ge *C, const secp256k1_scalar *a, const secp256k1_ge *B) {
    secp256k1_gej Cj;

    secp256k1_ecmult_gen_ge(ecmult_gen_ctx, A, a);
    secp256k1_ecmult_const(&Cj, B, a);
    secp256k1_ge_set_gej(C, &Cj);
}

/* DLEQ Proof Generation (internal)
 *
 * For given elliptic curve points A, B, C, and G, the prover generates a proof to prove knowledge of a scalar a such
 * that A = a⋅G and C = a⋅B without revealing anything about a.
 *
 *  Returns: 1 if proof creation was successful. 0 if an error occurred.
 *  Out: scalar e: part of proof = bytes(32, e) || bytes(32, s).
 *       scalar s: other part of proof = bytes(32, e) || bytes(32, s).
 *  In:     a : scalar a to be proven that both A and C were generated from
 *          B : point on the curve
 *          A : point on the curve(a⋅G) generated from a
 *          C : point on the curve(a⋅B) generated from a
 * aux_rand32 : pointer to 32-byte auxiliary randomness used to generate the nonce in secp256k1_nonce_function_dleq.
 *          m : an optional message
 * */
static int secp256k1_dleq_prove_internal(const secp256k1_context *ctx, secp256k1_scalar *e, secp256k1_scalar *s, const secp256k1_scalar *a, secp256k1_ge *B, secp256k1_ge *A, secp256k1_ge *C, const unsigned char *aux_rand32, const unsigned char *m) {
    const secp256k1_hash_ctx *hash_ctx = &ctx->hash_ctx;
    secp256k1_ge R1, R2;
    secp256k1_scalar k;
    unsigned char a32[32];
    unsigned char A_33[33];
    unsigned char C_33[33];
    int ret;

    /* Reject infinity points */
    if (secp256k1_ge_is_infinity(B) || secp256k1_ge_is_infinity(A) || secp256k1_ge_is_infinity(C)) {
        return 0;
    }
    secp256k1_scalar_get_b32(a32, a);
    secp256k1_ge_serialize33(A, A_33);
    secp256k1_ge_serialize33(C, C_33);
    ret = secp256k1_dleq_nonce(hash_ctx, &k, a32, A_33, C_33, aux_rand32, m);
    secp256k1_memclear_explicit(a32, sizeof(a32));
    /* The nonce is still secret here, but it being zero is less likely than 1:2^255. */
    secp256k1_declassify(ctx, &ret, sizeof(ret));
    if (!ret) {
        return 0;
    }

    /* R1 = k*G, R2 = k*B */
    secp256k1_dleq_pair(&ctx->ecmult_gen_ctx, &R1, &R2, &k, B);
    /* We declassify the non-secret values R1 and R2 to allow using them as
     * branch points. */
    secp256k1_declassify(ctx, &R1, sizeof(R1));
    secp256k1_declassify(ctx, &R2, sizeof(R2));

    /* e = tagged hash(A, B, C, R1, R2) */
    /* s = k + e * a */
    secp256k1_dleq_challenge(hash_ctx, e, A, B, C, &R1, &R2, m);
    secp256k1_scalar_mul(s, e, a);
    secp256k1_scalar_add(s, s, &k);

    secp256k1_scalar_clear(&k);
    return 1;
}

/* DLEQ Proof Verification (internal)
 *
 * Verifies the proof. If the following algorithm succeeds, the points A and C were both generated from the same scalar.
 * The former from multiplying by G, and the latter from multiplying by B.
 *
 *  Returns: 1 if proof verification was successful. 0 if an error occurred.
 *  In: scalar e : part of proof = bytes(32, e) || bytes(32, s)
 *      scalar s : other part of proof = bytes(32, e) || bytes(32, s)
 *          A : point on the curve(a⋅G) computed from a
 *          B : point on the curve
 *          C : point on the curve(a⋅B) computed from a
 *          m : optional message
 * */
static int secp256k1_dleq_verify_internal(const secp256k1_hash_ctx *hash_ctx, const secp256k1_scalar *e, const secp256k1_scalar *s, secp256k1_ge *A, secp256k1_ge *B, secp256k1_ge *C, const unsigned char *m) {
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
    /* R1 = s*G - e*A */
    secp256k1_ecmult(&R1j, &Aj, &e_neg, s);
    /* R2 = s*B - e*C */
    secp256k1_ecmult(&tmpj, &Cj, &e_neg, NULL);
    secp256k1_gej_set_ge(&Bj, B);
    secp256k1_ecmult(&R2j, &Bj, s, NULL);
    secp256k1_gej_add_var(&R2j, &R2j, &tmpj, NULL);

    /* Fail verification if R1j or R2j are infinity */
    if (secp256k1_gej_is_infinity(&R1j) || secp256k1_gej_is_infinity(&R2j)) {
        return 0;
    }
    secp256k1_ge_set_gej(&R1, &R1j);
    secp256k1_ge_set_gej(&R2, &R2j);
    secp256k1_dleq_challenge(hash_ctx, &e_expected, A, B, C, &R1, &R2, m);

    return secp256k1_scalar_eq(e, &e_expected);
}

int secp256k1_dleq_prove(
    const secp256k1_context *ctx,
    unsigned char *proof64,
    const unsigned char *seckey32,
    const secp256k1_pubkey *pubkey_B,
    const unsigned char *aux_rand32,
    const unsigned char *msg
) {
    secp256k1_scalar a, e, s;
    secp256k1_ge A, B, C;
    int is_sec_valid, ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(proof64 != NULL);
    ARG_CHECK(seckey32 != NULL);
    ARG_CHECK(pubkey_B != NULL);

    if (!secp256k1_pubkey_load(ctx, &B, pubkey_B)) {
        return 0;
    }

    is_sec_valid = secp256k1_scalar_set_b32_seckey(&a, seckey32);
    secp256k1_declassify(ctx, &is_sec_valid, sizeof(is_sec_valid));
    if (!is_sec_valid) {
        return 0;
    }

    secp256k1_dleq_pair(&ctx->ecmult_gen_ctx, &A, &C, &a, &B);
    /* A and C are the public statement that the proof is about: a verifier
     * needs both to check it. We declassify them to allow serializing them and
     * using them as branch points, just like R1 and R2 in prove_internal. */
    secp256k1_declassify(ctx, &A, sizeof(A));
    secp256k1_declassify(ctx, &C, sizeof(C));

    ret = secp256k1_dleq_prove_internal(ctx, &e, &s, &a, &B, &A, &C, aux_rand32, msg);
    secp256k1_scalar_clear(&a);
    if (!ret) {
        return 0;
    }

    secp256k1_scalar_get_b32(&proof64[0], &e);
    secp256k1_scalar_get_b32(&proof64[32], &s);

    return 1;
}

int secp256k1_dleq_verify(
    const secp256k1_context *ctx,
    const unsigned char *proof64,
    const secp256k1_pubkey *pubkey_A,
    const secp256k1_pubkey *pubkey_B,
    const secp256k1_pubkey *pubkey_C,
    const unsigned char *msg
) {
    secp256k1_scalar e, s;
    secp256k1_ge A, B, C;
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(proof64 != NULL);
    ARG_CHECK(pubkey_A != NULL);
    ARG_CHECK(pubkey_B != NULL);
    ARG_CHECK(pubkey_C != NULL);

    secp256k1_scalar_set_b32(&e, &proof64[0], &overflow);
    if (overflow) {
        return 0;
    }

    secp256k1_scalar_set_b32(&s, &proof64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_pubkey_load(ctx, &A, pubkey_A)) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &B, pubkey_B)) {
        return 0;
    }
    if (!secp256k1_pubkey_load(ctx, &C, pubkey_C)) {
        return 0;
    }

    return secp256k1_dleq_verify_internal(&ctx->hash_ctx, &e, &s, &A, &B, &C, msg);
}

#endif /* SECP256K1_MODULE_DLEQ_MAIN_H */
