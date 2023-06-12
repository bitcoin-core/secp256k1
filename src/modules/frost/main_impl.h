/***********************************************************************
 * Copyright (c) 2023 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_FROST_MAIN_H
#define SECP256K1_MODULE_FROST_MAIN_H

#include <sys/random.h>
#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_frost.h"

static const unsigned char hash_context_prefix_h1[29] = "FROST-secp256k1-SHA256-v11rho";
static const unsigned char hash_context_prefix_h3[31] = "FROST-secp256k1-SHA256-v11nonce";
static const unsigned char hash_context_prefix_h4[29] = "FROST-secp256k1-SHA256-v11msg";
static const unsigned char hash_context_prefix_h5[29] = "FROST-secp256k1-SHA256-v11com";

#define SCALAR_SIZE (32U)
#define SHA256_SIZE (32U)
#define SERIALIZED_PUBKEY_X_ONLY_SIZE (32U)
#define SERIALIZED_PUBKEY_XY_SIZE (64U)
#define ECMULT_CONST_256_BIT_SIZE 256

typedef struct {
    uint32_t index;
    uint32_t num_coefficients;
    secp256k1_scalar *coefficients;
} shamir_coefficients;

typedef struct {
    uint32_t num_binding_factors;
    uint32_t *participant_indexes;
    secp256k1_scalar *binding_factors;
    unsigned char **binding_factors_inputs;
} secp256k1_frost_binding_factors;

typedef struct {
    secp256k1_gej r;
    secp256k1_scalar z;
} secp256k1_frost_signature;

/* *********** *********** Section: Extension of secp256k1 functions *********** *********** */
static void secp256k1_ge_set_gej_safe(secp256k1_ge *r, const secp256k1_gej *a) {
    secp256k1_fe z2, z3;
    secp256k1_gej tmp;
    r->infinity = a->infinity;
    secp256k1_fe_inv(&tmp.z, &a->z);
    secp256k1_fe_sqr(&z2, &tmp.z);
    secp256k1_fe_mul(&z3, &tmp.z, &z2);
    secp256k1_fe_mul(&tmp.x, &a->x, &z2);
    secp256k1_fe_mul(&tmp.y, &a->y, &z3);
    secp256k1_fe_set_int(&tmp.z, 1);
    r->x = tmp.x;
    r->y = tmp.y;
}

static void secp256k1_gej_mul_scalar(secp256k1_gej *result, const secp256k1_gej *pt, const secp256k1_scalar *sc) {
    secp256k1_ge pt_ge;
    if (secp256k1_gej_is_infinity(pt)) {
        secp256k1_gej_set_infinity(result);
        return;
    }
    secp256k1_ge_set_gej_safe(&pt_ge, pt);
    secp256k1_ecmult_const(result, &pt_ge, sc, ECMULT_CONST_256_BIT_SIZE);
}

static SECP256K1_WARN_UNUSED_RESULT int secp256k1_gej_eq(const secp256k1_gej *a, const secp256k1_gej *b) {
    secp256k1_ge a_ge, b_ge;
    secp256k1_ge_set_gej_safe(&a_ge, a);
    secp256k1_ge_set_gej_safe(&b_ge, b);
    return (secp256k1_fe_equal(&(a_ge.x), &(b_ge.x)) && secp256k1_fe_equal(&(a_ge.y), &(b_ge.y)));
}

/* *********** *********** End of section: Extension of secp256k1 functions *********** *********** */
/*
 * Convert a 32-byte buffer to scalar.
 * Returns:
 *  1: if the conversion was successful and no overflow occurred
 *  0: otherwise
 */
static int convert_b32_to_scalar(const unsigned char *hash_value, secp256k1_scalar *output) {
    int overflow = 0;
    secp256k1_scalar_set_b32(output, hash_value, &overflow);
    if (overflow != 0) {
        return 0;
    }
    return 1;
}

static void serialize_point(const secp256k1_gej *point, unsigned char *output64) {
    secp256k1_ge normalized_point;
    secp256k1_ge_set_gej_safe(&normalized_point, point);
    VERIFY_CHECK(!normalized_point.infinity);
    secp256k1_fe_normalize_var(&normalized_point.x);
    secp256k1_fe_normalize_var(&normalized_point.y);
    secp256k1_fe_get_b32(output64, &normalized_point.x);
    secp256k1_fe_get_b32(output64 + SERIALIZED_PUBKEY_X_ONLY_SIZE, &normalized_point.y);
}

static void deserialize_point(secp256k1_gej *output, const unsigned char *point64) {
    secp256k1_ge normalized_point;
    secp256k1_fe_set_b32(&normalized_point.x, point64);
    secp256k1_fe_set_b32(&normalized_point.y, point64 + SERIALIZED_PUBKEY_X_ONLY_SIZE);
    normalized_point.infinity = 0;
    secp256k1_gej_set_ge(output, &normalized_point);
}

static void serialize_point_xonly(const secp256k1_gej *point, unsigned char *output) {
    secp256k1_ge commitment;
    secp256k1_ge_set_gej_safe(&commitment, point);
    secp256k1_fe_normalize_var(&(commitment.x));
    secp256k1_fe_get_b32(output, &(commitment.x));
}

static void serialize_scalar(const uint32_t value, unsigned char *ret) {
    secp256k1_scalar value_as_scalar;
    secp256k1_scalar_set_int(&value_as_scalar, value);
    secp256k1_scalar_get_b32(ret, &value_as_scalar);
}

static void serialize_frost_signature(unsigned char *output64,
                                      const secp256k1_frost_signature *signature) {
    serialize_point_xonly(&(signature->r), output64);
    secp256k1_scalar_get_b32(&output64[SERIALIZED_PUBKEY_X_ONLY_SIZE], &(signature->z));
}

static SECP256K1_WARN_UNUSED_RESULT int deserialize_frost_signature(secp256k1_frost_signature *signature,
                                                                    const unsigned char *serialized_signature) {
    secp256k1_fe x;
    secp256k1_ge deserialized_point;
    secp256k1_fe_set_b32(&x, serialized_signature);
    if (secp256k1_ge_set_xo_var(&deserialized_point, &x, 0) == 0) {
        return 0;
    }
    secp256k1_gej_set_ge(&(signature->r), &deserialized_point);
    if (convert_b32_to_scalar(&serialized_signature[SERIALIZED_PUBKEY_X_ONLY_SIZE], &(signature->z)) == 0) {
        return 0;
    }
    return 1;
}

static SECP256K1_WARN_UNUSED_RESULT int initialize_random_scalar(secp256k1_scalar *nonce) {
    /*
     * simplified from:
     * https://github.com/bitcoin/bitcoin/blob/747cdf1d652d8587e9f2e3d4436c3ecdbf56d0a5/src/secp256k1/examples/random.h
     * TODO: If `getrandom(2)` is not available you should fall back to /dev/urandom */
    unsigned char seed[SCALAR_SIZE];
    ssize_t random_bytes;
    random_bytes = getrandom(seed, SCALAR_SIZE, 0);
    if (random_bytes != SCALAR_SIZE) {
        return 0;
    }
    /* Overflow ignored on purpose */
    convert_b32_to_scalar(seed, nonce);
    return 1;
}

static void compute_hash_h1(const unsigned char *msg, uint32_t msg_len, unsigned char *hash_value) {
    /* TODO: replace with hash-to-curve
    * H1(m): Implemented using hash_to_field from [HASH-TO-CURVE], Section 5.3 using L = 48,
    * expand_message_xmd with SHA-256, DST = "FROST-secp256k1-SHA256-v11" || "rho", and prime modulus equal to Order(). */
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, hash_context_prefix_h1, sizeof(hash_context_prefix_h1));
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, hash_value);
}

static void compute_hash_h2(const unsigned char *msg, uint32_t msg_len, unsigned char *hash_value) {
    /* TODO: replace with hash-to-curve
    * H2(m): Implemented using hash_to_field from [HASH-TO-CURVE], Section 5.2 using L = 48,
    * expand_message_xmd with SHA-256, DST = "FROST-secp256k1-SHA256-v11" || "chal", and prime modulus equal to Order().*/
    const unsigned char prefix[17] = "BIP0340/challenge";
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, prefix, sizeof(prefix));
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, hash_value);
}

static void compute_hash_h3(const unsigned char *msg, uint32_t msg_len, unsigned char *hash_value) {
    /* TODO: replace with hash-to-curve
    * H3(m): Implemented using hash_to_field from [HASH-TO-CURVE], Section 5.2 using L = 48,
    * expand_message_xmd with SHA-256, DST = "FROST-secp256k1-SHA256-v11" || "nonce", and prime modulus equal to Order(). */
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, hash_context_prefix_h3, sizeof(hash_context_prefix_h3));
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, hash_value);
}

static void compute_hash_h4(const unsigned char *msg, uint32_t msg_len, unsigned char *hash_value) {
    /* H4(m): Implemented by computing H("FROST-secp256k1-SHA256-v11" || "msg" || m). */
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, hash_context_prefix_h4, sizeof(hash_context_prefix_h4));
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, hash_value);
}

static void compute_hash_h5(const unsigned char *msg, uint32_t msg_len, unsigned char *hash_value) {
    /* H5(m): Implemented by computing H("FROST-secp256k1-SHA256-v11" || "com" || m). */
    secp256k1_sha256 sha;
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, hash_context_prefix_h5, sizeof(hash_context_prefix_h5));
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, hash_value);
}

static void nonce_generate(unsigned char *out32, const secp256k1_frost_keypair *keypair,
                           const unsigned char *seed32) {
    unsigned char buffer[64] = {0};
    if (seed32 != NULL) {
        memcpy(buffer, seed32, SCALAR_SIZE);
    }
    memcpy(buffer + SCALAR_SIZE, keypair->secret, SCALAR_SIZE);
    compute_hash_h3(buffer, 64, out32);
    memset(buffer, 0, sizeof(buffer));
}

static int secp256k1_frost_expand_compact_pubkey(unsigned char *pubkey64,
                                                 const unsigned char *pubkey33) {
    secp256k1_ge elem;
    if (secp256k1_eckey_pubkey_parse(&elem, pubkey33, 33) == 0) {
        return 0;
    }
    secp256k1_fe_normalize_var(&elem.x);
    secp256k1_fe_normalize_var(&elem.y);
    secp256k1_fe_get_b32(pubkey64, &elem.x);
    secp256k1_fe_get_b32(pubkey64 + SERIALIZED_PUBKEY_X_ONLY_SIZE, &elem.y);
    return 1;
}

static void free_binding_factors(secp256k1_frost_binding_factors *binding_factors) {
    /* Free all allocated vars */
    free(binding_factors->binding_factors);
    free(binding_factors->binding_factors_inputs);
    free(binding_factors->participant_indexes);
}

SECP256K1_API int secp256k1_frost_pubkey_load(secp256k1_frost_pubkey *pubkey,
                                              const uint32_t index,
                                              const uint32_t max_participants,
                                              const unsigned char *pubkey33,
                                              const unsigned char *group_pubkey33) {
    if (pubkey == NULL || pubkey33 == NULL || group_pubkey33 == NULL) {
        return 0;
    }
    memset(pubkey, 0, sizeof(secp256k1_frost_pubkey));

    pubkey->index = index;
    pubkey->max_participants = max_participants;

    if (secp256k1_frost_expand_compact_pubkey(pubkey->public_key, pubkey33) == 0) {
        return 0;
    }
    if (secp256k1_frost_expand_compact_pubkey(pubkey->group_public_key, group_pubkey33) == 0) {
        return 0;
    }

    return 1;
}

SECP256K1_API int secp256k1_frost_pubkey_save(unsigned char *pubkey33,
                                              unsigned char *group_pubkey33,
                                              const secp256k1_frost_pubkey *pubkey) {
    size_t size;
    int compressed;
    secp256k1_ge pk, gpk;

    if (pubkey == NULL || pubkey33 == NULL || group_pubkey33 == NULL) {
        return 0;
    }
    compressed = 1;

    if (secp256k1_fe_set_b32(&pk.x, pubkey->public_key) == 0) {
        return 0;
    }
    if (secp256k1_fe_set_b32(&pk.y, pubkey->public_key + SERIALIZED_PUBKEY_X_ONLY_SIZE) == 0) {
        return 0;
    }

    pk.infinity = 0;
    /*
     * 0 is a purposely illegal value. We will verify that
     * secp256k1_eckey_pubkey_serialize() sets it to 33
     */
    size = 0;
    if (secp256k1_eckey_pubkey_serialize(&pk, pubkey33, &size, compressed) == 0) {
        return 0;
    }
    if (size != 33) {
        return 0;
    }
    secp256k1_ge_clear(&pk);

    if (secp256k1_fe_set_b32(&gpk.x, pubkey->group_public_key) == 0) {
        return 0;
    }
    if (secp256k1_fe_set_b32(&gpk.y, pubkey->group_public_key + SERIALIZED_PUBKEY_X_ONLY_SIZE) == 0) {
        return 0;
    }

    gpk.infinity = 0;
    /*
     * 0 is a purposely illegal value. We will verify that
     * secp256k1_eckey_pubkey_serialize() sets it to 33
     */
    size = 0;
    if (secp256k1_eckey_pubkey_serialize(&gpk, group_pubkey33, &size, compressed) == 0) {
        return 0;
    }
    if (size != 33) {
        return 0;
    }
    secp256k1_ge_clear(&gpk);

    return 1;
}

SECP256K1_API secp256k1_frost_vss_commitments *secp256k1_frost_vss_commitments_create(uint32_t threshold) {
    uint32_t num_coefficients;
    secp256k1_frost_vss_commitments *vss;
    if (threshold < 1) {
        return NULL;
    }
    num_coefficients = threshold - 1;
    vss = (secp256k1_frost_vss_commitments *) checked_malloc(&default_error_callback,
                                                             sizeof(secp256k1_frost_vss_commitments));
    vss->index = 0;
    memset(vss->zkp_z, 0, SCALAR_SIZE);
    memset(vss->zkp_r, 0, 64);

    vss->num_coefficients = num_coefficients + 1;
    vss->coefficient_commitments = (secp256k1_frost_vss_commitment *)
            checked_malloc(&default_error_callback, (num_coefficients + 1) * sizeof(secp256k1_frost_vss_commitment));
    return vss;
}

SECP256K1_API void secp256k1_frost_vss_commitments_destroy(secp256k1_frost_vss_commitments *vss_commitments) {
    if (vss_commitments == NULL) {
        return;
    }

    vss_commitments->index = 0;
    vss_commitments->num_coefficients = 0;
    memset(vss_commitments->zkp_z, 0, SCALAR_SIZE);
    memset(vss_commitments->zkp_r, 0, SERIALIZED_PUBKEY_XY_SIZE);
    free(vss_commitments->coefficient_commitments);
    free(vss_commitments);
}

static SECP256K1_WARN_UNUSED_RESULT shamir_coefficients *shamir_coefficients_create(uint32_t threshold) {
    const uint32_t num_coefficients = threshold - 1;
    shamir_coefficients *s;
    s = (shamir_coefficients *) checked_malloc(&default_error_callback,
                                               sizeof(shamir_coefficients));
    s->index = 0;
    s->num_coefficients = num_coefficients;
    s->coefficients = (secp256k1_scalar *)
            checked_malloc(&default_error_callback, num_coefficients * sizeof(secp256k1_scalar));
    return s;
}

static void shamir_coefficients_destroy(shamir_coefficients *coefficients) {
    if (coefficients == NULL) {
        return;
    }

    coefficients->index = 0;
    coefficients->num_coefficients = 0;
    free(coefficients->coefficients);
    free(coefficients);
}

SECP256K1_API secp256k1_frost_nonce *secp256k1_frost_nonce_create(const secp256k1_context *ctx,
                                                                  const secp256k1_frost_keypair *keypair,
                                                                  const unsigned char *binding_seed32,
                                                                  const unsigned char *hiding_seed32) {
    secp256k1_scalar hiding, binding;
    secp256k1_gej hiding_cmt, binding_cmt;
    secp256k1_frost_nonce *nonce;
    if (EXPECT(ctx == NULL, 0) || EXPECT(keypair == NULL, 0)
        || EXPECT(binding_seed32 == NULL, 0) || EXPECT(hiding_seed32 == NULL, 0)) {
        return NULL;
    }

    nonce = (secp256k1_frost_nonce *) checked_malloc(&default_error_callback,
                                                     sizeof(secp256k1_frost_nonce));
    if (EXPECT(nonce == NULL, 0)) {
        free(nonce);
        return NULL;
    }
    /* Initialize random nonces */
    nonce_generate(nonce->binding, keypair, binding_seed32);
    nonce_generate(nonce->hiding, keypair, hiding_seed32);
    secp256k1_scalar_set_b32(&binding, nonce->binding, NULL);
    secp256k1_scalar_set_b32(&hiding, nonce->hiding, NULL);

    /* Compute commitments */
    (nonce->commitments).index = keypair->public_keys.index;
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &binding_cmt, &binding);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &hiding_cmt, &hiding);
    serialize_point(&binding_cmt, nonce->commitments.binding);
    serialize_point(&hiding_cmt, nonce->commitments.hiding);

    nonce->used = 0;
    return nonce;
}

SECP256K1_API void secp256k1_frost_nonce_destroy(secp256k1_frost_nonce *nonce) {
    if (nonce == NULL) {
        return;
    }

    memset(nonce->binding, 0, SCALAR_SIZE);
    memset(nonce->hiding, 0, SCALAR_SIZE);
    nonce->commitments.index = 0;
    memset(nonce->commitments.binding, 0, SERIALIZED_PUBKEY_XY_SIZE);
    memset(nonce->commitments.hiding, 0, SERIALIZED_PUBKEY_XY_SIZE);
    free(nonce);
}

SECP256K1_API secp256k1_frost_keypair *secp256k1_frost_keypair_create(uint32_t participant_index) {
    secp256k1_frost_keypair *kp = (secp256k1_frost_keypair *) checked_malloc(&default_error_callback,
                                                                             sizeof(secp256k1_frost_keypair));
    if (EXPECT(kp == NULL, 0)) {
        free(kp);
        return NULL;
    }
    kp->public_keys.index = participant_index;
    memset(kp->secret, 0, SCALAR_SIZE);
    memset(kp->public_keys.public_key, 0, SERIALIZED_PUBKEY_XY_SIZE);
    memset(kp->public_keys.group_public_key, 0, SERIALIZED_PUBKEY_XY_SIZE);
    kp->public_keys.max_participants = 0;
    return kp;
}

SECP256K1_API void secp256k1_frost_keypair_destroy(secp256k1_frost_keypair *keypair) {
    if (keypair == NULL) {
        return;
    }

    free(keypair);
}

/*
 * Generate coefficients for Shamir Secret Sharing.
 *
 *  Returns: 1: on success; 0: on failure
 *  Args:            ctx: a secp256k1 context object, initialized for verification.
 *  Out: dkg_commitments: pointer to shamir_coefficients where coefficients will be stored.
 *          coefficients: pointer to shamir_coefficients where coefficients will be stored.
 *  In:  generator_index: index of participant generating coefficients.
 *                secret: secret to be used as known term of the Shamir polynomial
 *      num_participants: number of participants to the secret sharing
 *             threshold: min number of participants needed to reconstruct the secret.
 */
static SECP256K1_WARN_UNUSED_RESULT int generate_coefficients(const secp256k1_context *ctx,
                                                              secp256k1_frost_vss_commitments *dkg_commitments,
                                                              shamir_coefficients *coefficients,
                                                              uint32_t generator_index, const secp256k1_scalar *secret,
                                                              uint32_t threshold) {
    uint32_t c_idx;
    secp256k1_gej coefficient_cmt;
    const uint32_t num_coefficients = threshold - 1;

    coefficients->index = generator_index;
    dkg_commitments->index = generator_index;

    /* Compute the commitment of the secret term (saved as commitment[0]) */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &coefficient_cmt, secret);
    serialize_point(&coefficient_cmt, dkg_commitments->coefficient_commitments[0].data);

    for (c_idx = 0; c_idx < num_coefficients; c_idx++) {
        /* Generate random coefficients */
        if (initialize_random_scalar(&(coefficients->coefficients[c_idx])) == 0) {
            return 0;
        }

        /* Compute the commitment of each random coefficient (saved as commitment[1...]) */
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx,
                             &coefficient_cmt,
                             &(coefficients->coefficients[c_idx]));
        serialize_point(&coefficient_cmt, dkg_commitments->coefficient_commitments[c_idx + 1].data);
    }
    return 1;
}

/*
 * Evaluate Shamir polynomial for each participant.
 *
 *  Returns: 1: on success; 0: on failure
 *  Out:   shares: pointer to shamir_coefficients where coefficients will be stored (expected to be already allocated).
 *  In:   coefficients: pointer to shamir_coefficients where coefficients will be stored.
 *     generator_index: index of participant generating coefficients.
 *    num_participants: number of participants to the secret sharing
 *        coefficients: pointer to shamir_coefficients.
 *              secret: secret to be used as known term of the Shamir polynomial.
 */
static void evaluate_shamir_polynomial(secp256k1_frost_keygen_secret_share *shares,
                                       uint32_t generator_index, uint32_t num_participants,
                                       const shamir_coefficients *coefficients, const secp256k1_scalar *secret) {
    /* For each participant, evaluate the polynomial and save in shares:
     * {generator_index, participant_index, f(participant_index)} */
    uint32_t index;
    for (index = 1; index < num_participants + 1; index++) {
        /* Evaluate the polynomial with `secret` as the constant term
         * and `coefficients` as the other coefficients at the point x=share_index
         * using Horner's method */
        secp256k1_scalar scalar_index;
        secp256k1_scalar value;
        uint32_t c_idx;

        secp256k1_scalar_set_int(&scalar_index, index);
        secp256k1_scalar_set_int(&value, 0);
        for (c_idx = coefficients->num_coefficients; c_idx > 0; c_idx--) {
            secp256k1_scalar_add(&value, &value, &(coefficients->coefficients[c_idx - 1]));
            secp256k1_scalar_mul(&value, &value, &scalar_index);
        }

        /* The secret is the *constant* term in the polynomial used for secret sharing,
         * this is typical in schemes that build upon Shamir Secret Sharing. */
        secp256k1_scalar_add(&value, &value, secret);
        secp256k1_scalar_get_b32(shares[index - 1].value, &value);

        shares[index - 1].generator_index = generator_index;
        shares[index - 1].receiver_index = index;
    }
}

/*
 * Generate a random polynomial f for generator_index, commit to the secret and to each f coefficients,
 * and f(p) for each participant p
 *
 * Returns 1 on success, 0 on failure.
 *  Args:            ctx: pointer to a context object, initialized for signing.
 *  Out:    coefficients: commitments to the Shamir polynomial coefficients.
 *                shares: array containing the polynomial computed for each participant (expected to be allocated)
 *  In: num_participants: number of shares and commitments.
 *             threshold: Signature threshold
 *       generator_index: participant index.
 *                secret: Secret value to use as constant term of the polynomial
 */
static SECP256K1_WARN_UNUSED_RESULT int generate_shares(const secp256k1_context *ctx,
                                                        secp256k1_frost_vss_commitments *dkg_commitments,
                                                        secp256k1_frost_keygen_secret_share *shares,
                                                        uint32_t num_participants, uint32_t threshold,
                                                        uint32_t generator_index,
                                                        const secp256k1_scalar *secret) {
    int ret_coefficients;
    shamir_coefficients *coefficients;
    coefficients = shamir_coefficients_create(threshold);

    ret_coefficients = generate_coefficients(ctx, dkg_commitments, coefficients, generator_index, secret, threshold);
    if (ret_coefficients == 1) {
        evaluate_shamir_polynomial(shares, generator_index,
                                   num_participants, coefficients, secret);
    }

    shamir_coefficients_destroy(coefficients);
    return ret_coefficients;
}

/*
 * Generate a challenge for DKG.
 *
 * Returns 1 on success, 0 on failure.
 *  Out:  challenge: pointer to scalar where the challenge will be stored.
 *  In:       index: participant identifier.
 *    context_nonce: tag to use during DKG
 *     nonce_length: tag length
 *       public_key: participant public key used for computing the challenge.
 *       commitment: commitment to a random value.
 */
static SECP256K1_WARN_UNUSED_RESULT int generate_dkg_challenge(secp256k1_scalar *challenge,
                                                               const uint32_t index, const unsigned char *context_nonce,
                                                               const uint32_t nonce_length,
                                                               const secp256k1_gej *public_key,
                                                               const secp256k1_gej *commitment) {
    uint32_t challenge_input_length;
    unsigned char *challenge_input;
    unsigned char hash_value[SHA256_SIZE];
    secp256k1_sha256 sha;

    /* challenge_input = commitment || pk || index || context_nonce */
    challenge_input_length = SERIALIZED_PUBKEY_X_ONLY_SIZE + SERIALIZED_PUBKEY_X_ONLY_SIZE + SCALAR_SIZE + nonce_length;
    challenge_input = (unsigned char *) checked_malloc(&default_error_callback, challenge_input_length);

    serialize_point_xonly(commitment, challenge_input);
    serialize_point_xonly(public_key, &(challenge_input[SERIALIZED_PUBKEY_X_ONLY_SIZE]));
    serialize_scalar(index, &(challenge_input[SERIALIZED_PUBKEY_X_ONLY_SIZE + SERIALIZED_PUBKEY_X_ONLY_SIZE]));
    memcpy(&challenge_input[SERIALIZED_PUBKEY_X_ONLY_SIZE + SERIALIZED_PUBKEY_X_ONLY_SIZE + SCALAR_SIZE],
           context_nonce, nonce_length);

    /* compute hash of the challenge_input */
    secp256k1_sha256_initialize(&sha);
    secp256k1_sha256_write(&sha, challenge_input, challenge_input_length);
    secp256k1_sha256_finalize(&sha, hash_value);

    /* save hash value as scalar (overflow ignored on purpose) */
    convert_b32_to_scalar(hash_value, challenge);

    /* cleaning out the input buffer */
    if (challenge_input != NULL) {
        free(challenge_input);
    }
    return 1;
}

static SECP256K1_WARN_UNUSED_RESULT int is_valid_zkp(const secp256k1_context *ctx, const secp256k1_scalar *challenge,
                                                     const secp256k1_frost_vss_commitments *commitment) {
    secp256k1_gej reference, z_commitment, commitment_challenge, zkp_r, coefficient_commitment;
    secp256k1_scalar z;

    deserialize_point(&coefficient_commitment, commitment->coefficient_commitments[0].data);
    secp256k1_scalar_set_b32(&z, commitment->zkp_z, NULL);
    secp256k1_ecmult_gen(&(ctx->ecmult_gen_ctx), &z_commitment, &z);
    secp256k1_gej_mul_scalar(&commitment_challenge, &coefficient_commitment, challenge);
    secp256k1_gej_neg(&commitment_challenge, &commitment_challenge);
    secp256k1_gej_add_var(&reference, &z_commitment, &commitment_challenge, NULL);

    deserialize_point(&zkp_r, commitment->zkp_r);
    return secp256k1_gej_eq(&zkp_r, &reference);
}

/* TODO: to improve testability of this function, it should be deterministic. */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_dkg_begin(const secp256k1_context *ctx,
                                                                                secp256k1_frost_vss_commitments *dkg_commitment,
                                                                                secp256k1_frost_keygen_secret_share *shares,
                                                                                uint32_t num_participants,
                                                                                uint32_t threshold,
                                                                                uint32_t generator_index,
                                                                                const unsigned char *context,
                                                                                uint32_t context_length) {
    secp256k1_scalar secret, r, z, challenge;
    secp256k1_gej s_pub, zkp_r;

    if (ctx == NULL || dkg_commitment == NULL || shares == NULL || context == NULL) {
        return 0;
    }
    if (threshold < 1 || num_participants < 1 || threshold > num_participants) {
        return 0;
    }

    dkg_commitment->index = generator_index;
    if (initialize_random_scalar(&secret) == 0) {
        return 0;
    }
    if (generate_shares(ctx, dkg_commitment, shares, num_participants,
                        threshold, generator_index, &secret) == 0) {
        return 0;
    }

    if (initialize_random_scalar(&r) == 0) {
        return 0;
    }
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &s_pub, &secret);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &zkp_r, &r);
    serialize_point(&zkp_r, dkg_commitment->zkp_r);
    if (generate_dkg_challenge(&challenge, generator_index, context, context_length, &s_pub, &zkp_r) == 0) {
        return 0;
    }

    /* z = r + secret * H(context, G^secret, G^r) */
    secp256k1_scalar_mul(&z, &secret, &challenge);
    secp256k1_scalar_add(&z, &r, &z);
    secp256k1_scalar_get_b32(dkg_commitment->zkp_z, &z);

    /* Cleaning context */
    secp256k1_scalar_set_int(&secret, 0);
    secp256k1_scalar_set_int(&r, 0);
    return 1;
}

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_dkg_commitment_validate(
        const secp256k1_context *ctx,
        const secp256k1_frost_vss_commitments *peer_commitment,
        const unsigned char *context, uint32_t context_length) {
    secp256k1_scalar challenge;
    secp256k1_gej peer_zkp_r, secret_commitment;

    if (ctx == NULL || peer_commitment == NULL || context == NULL) {
        return 0;
    }

    deserialize_point(&peer_zkp_r, peer_commitment->zkp_r);
    deserialize_point(&secret_commitment, peer_commitment->coefficient_commitments[0].data);
    if (generate_dkg_challenge(&challenge, peer_commitment->index,
                               context, context_length,
                               &secret_commitment,
                               &peer_zkp_r) == 0) {
        return 0;
    }
    return is_valid_zkp(ctx, &challenge, peer_commitment);
}

static SECP256K1_WARN_UNUSED_RESULT int verify_secret_share(const secp256k1_context *ctx,
                                                            const secp256k1_frost_keygen_secret_share *share,
                                                            const secp256k1_frost_vss_commitments *commitment) {
    secp256k1_scalar x, x_to_the_i, scalar_share_value;
    secp256k1_gej f_result, result;
    uint32_t index;

    secp256k1_scalar_set_b32(&scalar_share_value, share->value, NULL);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &f_result, &scalar_share_value);

    secp256k1_scalar_set_int(&x, share->receiver_index);
    secp256k1_scalar_set_int(&x_to_the_i, 1);
    secp256k1_gej_set_infinity(&result);
    secp256k1_gej_mul_scalar(&result, &result, &x_to_the_i);

    for (index = 0; index < commitment->num_coefficients; index++) {
        secp256k1_gej current;
        deserialize_point(&current, commitment->coefficient_commitments[index].data);
        secp256k1_gej_mul_scalar(&current, &current, &x_to_the_i);
        secp256k1_gej_add_var(&result, &result, &current, NULL);
        secp256k1_scalar_mul(&x_to_the_i, &x_to_the_i, &x);
    }
    return secp256k1_gej_eq(&f_result, &result);
}

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_dkg_finalize(
        const secp256k1_context *ctx,
        secp256k1_frost_keypair *keypair,
        uint32_t index,
        uint32_t num_participants,
        const secp256k1_frost_keygen_secret_share *shares,
        secp256k1_frost_vss_commitments **commitments) {
    uint32_t s_idx, c_idx;
    secp256k1_scalar scalar_unit, scalar_secret;
    secp256k1_gej pubkey, group_pubkey;

    if (ctx == NULL || keypair == NULL || shares == NULL || commitments == NULL) {
        return 0;
    }

    keypair->public_keys.index = index;
    for (s_idx = 0; s_idx < num_participants; s_idx++) {
        for (c_idx = 0; c_idx < num_participants; c_idx++) {
            if (shares[s_idx].generator_index == commitments[c_idx]->index) {
                if (verify_secret_share(ctx, &shares[s_idx], commitments[c_idx]) == 0) {
                    return 0;
                }
            }
        }
    }

    secp256k1_scalar_set_int(&scalar_secret, 0);
    for (s_idx = 0; s_idx < num_participants; s_idx++) {
        secp256k1_scalar scalar_share_value;
        secp256k1_scalar_set_b32(&scalar_share_value, shares[s_idx].value, NULL);
        secp256k1_scalar_add(&scalar_secret, &scalar_secret, &scalar_share_value);
    }
    secp256k1_scalar_get_b32(keypair->secret, &scalar_secret);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubkey, &scalar_secret);
    serialize_point(&pubkey, keypair->public_keys.public_key);

    secp256k1_gej_set_infinity(&group_pubkey);
    secp256k1_scalar_set_int(&scalar_unit, 1);
    secp256k1_gej_mul_scalar(&group_pubkey,
                             &group_pubkey, &scalar_unit);

    for (c_idx = 0; c_idx < num_participants; c_idx++) {
        secp256k1_gej secret_commitment;
        deserialize_point(&secret_commitment, commitments[c_idx]->coefficient_commitments[0].data);
        secp256k1_gej_add_var(&group_pubkey, &group_pubkey, &secret_commitment, NULL);
    }
    serialize_point(&group_pubkey, keypair->public_keys.group_public_key);
    keypair->public_keys.max_participants = num_participants;
    return 1;
}

SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_keygen_with_dealer(
        const secp256k1_context *ctx,
        secp256k1_frost_vss_commitments *share_commitment,
        secp256k1_frost_keygen_secret_share *shares,
        secp256k1_frost_keypair *keypairs,
        uint32_t num_participants,
        uint32_t threshold) {

    secp256k1_scalar secret;
    secp256k1_gej group_public_key;
    uint32_t generator_index, index;

    if (ctx == NULL || share_commitment == NULL || shares == NULL || keypairs == NULL) {
        return 0;
    }

    /* We use generator_index=0 as we are generating shares with a dealer */
    generator_index = 0;

    /* Parameter checking */
    if (threshold < 1 || num_participants < 1 || threshold > num_participants) {
        return 0;
    }

    /* Initialization */
    share_commitment->index = generator_index;
    if (initialize_random_scalar(&secret) == 0) {
        return 0;
    }
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &group_public_key, &secret);

    /* Generate shares */
    if (generate_shares(ctx, share_commitment, shares, num_participants,
                        threshold, generator_index, &secret) == 0) {
        return 0;
    }

    /* Preparing output */
    for (index = 0; index < num_participants; index++) {
        secp256k1_scalar share_value;
        secp256k1_gej pubkey;

        secp256k1_scalar_set_b32(&share_value, shares[index].value, NULL);
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &pubkey, &share_value);
        serialize_point(&pubkey, keypairs[index].public_keys.public_key);

        memcpy(&keypairs[index].secret, &shares[index].value, SCALAR_SIZE);
        serialize_point(&group_public_key, keypairs[index].public_keys.group_public_key);
        keypairs[index].public_keys.index = shares[index].receiver_index;
        keypairs[index].public_keys.max_participants = num_participants;
    }
    return 1;
}

static SECP256K1_WARN_UNUSED_RESULT int signing_commitment_compare(secp256k1_frost_nonce_commitment *s1,
                                                                   secp256k1_frost_nonce_commitment *s2) {
    if (s1->index > s2->index) {
        return 1;
    }
    if (s1->index < s2->index) {
        return -1;
    }
    return 0;
}

static void signing_commitment_swap(secp256k1_frost_nonce_commitment *v1, secp256k1_frost_nonce_commitment *v2) {
    uint32_t size;
    secp256k1_frost_nonce_commitment buffer;

    size = sizeof(secp256k1_frost_nonce_commitment);
    memcpy(&buffer, v1, size);
    memcpy(v1, v2, size);
    memcpy(v2, &buffer, size);
}

static SECP256K1_WARN_UNUSED_RESULT int signing_commitment_partition(secp256k1_frost_nonce_commitment *v, int p, int q) {
    int i, j;
    i = p;
    j = q;
    while (i <= j) {
        while (signing_commitment_compare(&v[j], &v[p]) > 0) { j--; }
        while (i <= j && signing_commitment_compare(&v[i], &v[p]) <= 0) { i++; }
        if (i < j) {
            signing_commitment_swap(&v[i], &v[j]);
            i++;
            j--;
        }
    }
    signing_commitment_swap(&v[p], &v[j]);
    return j;
}

static void signing_commitment_sort(secp256k1_frost_nonce_commitment *v, int p, int q) {
    int l;
    l = signing_commitment_partition(v, p, q);
    if ((l - p) < (q - l)) {
        if (p < (l - 1)) { signing_commitment_sort(v, p, l - 1); }
        if ((l + 1) < q) { signing_commitment_sort(v, l + 1, q); }
    } else {
        if ((l + 1) < q) { signing_commitment_sort(v, l + 1, q); }
        if (p < (l - 1)) { signing_commitment_sort(v, p, l - 1); }
    }
}

static SECP256K1_WARN_UNUSED_RESULT int compute_group_commitment(/* out */ secp256k1_gej *group_commitment,
        /* out */ int *is_group_commitment_odd,
                                                                           uint32_t num_signers,
                                                                           const secp256k1_frost_binding_factors *binding_factors,
                                                                           const secp256k1_frost_nonce_commitment *signing_commitments) {
    secp256k1_scalar scalar_unit;
    secp256k1_gej hiding_cmt, binding_cmt;
    uint32_t index, inner_index;

    secp256k1_scalar_set_int(&scalar_unit, 1);
    secp256k1_gej_set_infinity(group_commitment);
    secp256k1_gej_mul_scalar(group_commitment, group_commitment, &scalar_unit);

    for (index = 0; index < num_signers; index++) {
        secp256k1_scalar *rho_i;
        secp256k1_gej partial;
        int found;
        const secp256k1_frost_nonce_commitment *commitment;

        commitment = &signing_commitments[index];
        found = 0;
        for (inner_index = 0; inner_index < binding_factors->num_binding_factors; inner_index++) {
            if (binding_factors->participant_indexes[inner_index] == commitment->index) {
                rho_i = &binding_factors->binding_factors[inner_index];
                found = 1;
                break;
            }
        }
        if (found == 0) {
            return 0;
        }

        secp256k1_gej_set_infinity(&partial);
        secp256k1_gej_mul_scalar(&partial, &partial, &scalar_unit);

        /* group_commitment += commitment.d + (commitment.e * rho_i) */
        deserialize_point(&hiding_cmt, commitment->hiding);
        deserialize_point(&binding_cmt, commitment->binding);
        secp256k1_gej_mul_scalar(&partial, &binding_cmt, rho_i);
        secp256k1_gej_add_var(&partial, &hiding_cmt, &partial, NULL);

        secp256k1_gej_add_var(group_commitment, group_commitment, &partial, NULL);
    }

    /*
     * No matter if we tweaked the public key or not, the nonce commitment
     * could potentially have an odd y-coordinate which is not acceptable,
     * since as per BIP-340 the Y coordinate of P (public key) and R (nonce
     * commitment) are implicitly chosen to be even.
     * Hence, if nonce_commitment y-coordinate is odd we need to negate it
    */
    {
        secp256k1_ge group_commitment_ge;
        secp256k1_ge_set_gej_safe(&group_commitment_ge, group_commitment);
        secp256k1_fe_normalize_var(&group_commitment_ge.y);
        (*is_group_commitment_odd) = secp256k1_fe_is_odd(&group_commitment_ge.y);
    };
    return 1;
}

static void compute_challenge(secp256k1_scalar *challenge,
                              const unsigned char *msg, uint32_t msg_len,
                              const secp256k1_gej *group_public_key,
                              const secp256k1_gej *group_commitment) {
    unsigned char buf[SCALAR_SIZE];
    unsigned char rx[SERIALIZED_PUBKEY_X_ONLY_SIZE];
    unsigned char pk[SERIALIZED_PUBKEY_X_ONLY_SIZE];
    secp256k1_sha256 sha;

    serialize_point_xonly(group_commitment, rx);
    serialize_point_xonly(group_public_key, pk);

    secp256k1_sha256_initialize(&sha);
    sha.s[0] = 0x9cecba11ul;
    sha.s[1] = 0x23925381ul;
    sha.s[2] = 0x11679112ul;
    sha.s[3] = 0xd1627e0ful;
    sha.s[4] = 0x97c87550ul;
    sha.s[5] = 0x003cc765ul;
    sha.s[6] = 0x90f61164ul;
    sha.s[7] = 0x33e9b66aul;
    sha.bytes = 64;

    secp256k1_sha256_write(&sha, rx, SERIALIZED_PUBKEY_X_ONLY_SIZE);
    secp256k1_sha256_write(&sha, pk, SERIALIZED_PUBKEY_X_ONLY_SIZE);
    secp256k1_sha256_write(&sha, msg, msg_len);
    secp256k1_sha256_finalize(&sha, buf);
    secp256k1_scalar_set_b32(challenge, buf, NULL);
}

static void encode_group_commitments(
        /* out */ unsigned char *buffer,
                  uint32_t num_signers,
                  const secp256k1_frost_nonce_commitment *signing_commitments) {
    uint32_t index;
    uint32_t item_size;
    uint32_t identifier_idx, hiding_idx, binding_idx;
    secp256k1_frost_nonce_commitment item;

    index = 0;
    item_size = (SCALAR_SIZE + SERIALIZED_PUBKEY_X_ONLY_SIZE + SERIALIZED_PUBKEY_X_ONLY_SIZE);

    for (index = 0; index < num_signers; index++) {
        secp256k1_gej hiding_cmt, binding_cmt;
        item = signing_commitments[index];
        identifier_idx = item_size * index;
        hiding_idx = SCALAR_SIZE + item_size * index;
        binding_idx = SCALAR_SIZE + SERIALIZED_PUBKEY_X_ONLY_SIZE + item_size * index;

        serialize_scalar(item.index, &(buffer[identifier_idx]));
        deserialize_point(&hiding_cmt, item.hiding);
        serialize_point_xonly(&hiding_cmt, &(buffer[hiding_idx]));
        deserialize_point(&binding_cmt, item.binding);
        serialize_point_xonly(&binding_cmt, &(buffer[binding_idx]));
    }
}

/* TODO: H4(msg) and H5(encoded_group_commitments) is the same for each participant; move in
 * compute_binding_factors */
static void compute_binding_factor(
        /* out */ secp256k1_scalar *binding_factor,
                  uint32_t index,
                  const unsigned char *msg, uint32_t msg_len,
                  uint32_t num_signers,
                  const secp256k1_frost_nonce_commitment *signing_commitments) {

    unsigned char rho_input[SHA256_SIZE + SHA256_SIZE + SCALAR_SIZE] = {0};

    /* Compute H4 of message */
    unsigned char binding_factor_hash[SHA256_SIZE];
    uint32_t encoded_group_commitments_size;
    unsigned char *encoded_group_commitments;

    /* unsigned char rho_input[SHA256_SIZE + SHA256_SIZE + SCALAR_SIZE]; */
    compute_hash_h4(msg, msg_len, rho_input);

    encoded_group_commitments_size = num_signers * (SCALAR_SIZE +
                                                    SERIALIZED_PUBKEY_X_ONLY_SIZE + SERIALIZED_PUBKEY_X_ONLY_SIZE);
    encoded_group_commitments = (unsigned char *) checked_malloc(&default_error_callback,
                                                                 encoded_group_commitments_size);
    encode_group_commitments(encoded_group_commitments, num_signers, signing_commitments);
    compute_hash_h5(encoded_group_commitments, encoded_group_commitments_size, &(rho_input[SHA256_SIZE]));

    free(encoded_group_commitments);

    /* rho_input = msg_hash || encoded_commitment_hash || serialize_scalar(identifier) */
    serialize_scalar(index, &(rho_input[SHA256_SIZE + SHA256_SIZE]));

    /* Compute binding factor for participant (index); binding_factor = H.H1(rho_input) */
    compute_hash_h1(rho_input, SHA256_SIZE + SHA256_SIZE + SCALAR_SIZE, binding_factor_hash);

    /* Convert to scalar (overflow ignored on purpose) */
    convert_b32_to_scalar(binding_factor_hash, binding_factor);
}

static SECP256K1_WARN_UNUSED_RESULT int compute_binding_factors(
                                  /* out */ secp256k1_frost_binding_factors *binding_factors,
                                  const unsigned char *msg32,
                                  uint32_t msg_len,
                                  uint32_t num_signers,
                                  secp256k1_frost_nonce_commitment *signing_commitments) {
    uint32_t index;
    if (num_signers == 0) {
        return 0;
    }
    binding_factors->num_binding_factors = num_signers;

    /* Note: this sorting is performed in place; but this is acceptable. */
    signing_commitment_sort(signing_commitments, 0, ((int32_t) num_signers) - 1);

    for (index = 0; index < num_signers; index++) {
        compute_binding_factor(&(binding_factors->binding_factors[index]),
                               signing_commitments[index].index, msg32, msg_len,
                               num_signers, signing_commitments);

        binding_factors->participant_indexes[index] = signing_commitments[index].index;
        /*TODO: save rho_input in binding_factors; define an allocation strategy */
    }

    return 1;
}

static SECP256K1_WARN_UNUSED_RESULT int derive_interpolating_value(/* out */ secp256k1_scalar *lambda_i,
                                                                             const uint32_t signer_index,
                                                                             uint32_t num_signers,
                                                                             const uint32_t *all_signer_indices) {
    secp256k1_scalar num, den, den_inverse;
    uint32_t index;

    secp256k1_scalar_set_int(lambda_i, 0);
    secp256k1_scalar_set_int(&num, 1);
    secp256k1_scalar_set_int(&den, 1);

    for (index = 0; index < num_signers; ++index) {
        secp256k1_scalar scalar_j;
        secp256k1_scalar den_contribution;
        secp256k1_scalar scalar_signer_index, scalar_signer_index_neg;

        if (all_signer_indices[index] == signer_index) {
            continue;
        }

        /* num *= x_j  */
        secp256k1_scalar_set_int(&scalar_j, all_signer_indices[index]);
        secp256k1_scalar_mul(&num, &num, &scalar_j);

        /* den *= x_j - signer_index */
        secp256k1_scalar_set_int(&scalar_j, all_signer_indices[index]);
        secp256k1_scalar_set_int(&scalar_signer_index, signer_index);
        secp256k1_scalar_negate(&scalar_signer_index_neg, &scalar_signer_index);
        secp256k1_scalar_add(&den_contribution, &scalar_j, &scalar_signer_index_neg);
        secp256k1_scalar_mul(&den, &den, &den_contribution);
    }

    if (secp256k1_scalar_is_zero(&den)) {
        return 0;
    }

    secp256k1_scalar_inverse(&den_inverse, &den);
    secp256k1_scalar_mul(lambda_i, &num, &den_inverse);

    return 1;
}

static SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_sign_internal(
                                         /* out: */ secp256k1_frost_signature_share *response,
                                         const unsigned char *msg32,
                                         uint32_t num_signers,
                                         const secp256k1_frost_keypair *keypair,
                                         const secp256k1_frost_nonce *nonce,
                                         const secp256k1_frost_nonce_commitment *signing_commitments,
                                         const secp256k1_frost_binding_factors *bindings) {
    secp256k1_gej group_commitment, group_pubkey;
    secp256k1_scalar lambda_i, c, sig_share, term1, term2, secret, hiding, binding;
    secp256k1_scalar *my_rho_i;
    int is_group_commitment_odd;
    uint32_t index;

    /* Compute the group commitment */
    if (compute_group_commitment(&group_commitment, &is_group_commitment_odd,
                                 num_signers, bindings, signing_commitments) == 0) {
        return 0;
    }
    /* Compute Lagrange coefficient */
    if (derive_interpolating_value(&lambda_i, keypair->public_keys.index,
                                   num_signers, bindings->participant_indexes) == 0) {
        return 0;
    }

    /* Compute the per-message challenge */
    deserialize_point(&group_pubkey, keypair->public_keys.group_public_key);
    compute_challenge(&c, msg32, 32, &group_pubkey, &(group_commitment));

    /* Compute the signature share */
    my_rho_i = NULL;
    for (index = 0; index < num_signers; index++) {
        if (bindings->participant_indexes[index] == keypair->public_keys.index) {
            my_rho_i = &(bindings->binding_factors[index]);
            break;
        }
    }
    if (my_rho_i == NULL) {
        return 0;
    }
    secp256k1_scalar_set_int(&sig_share, 0);
    secp256k1_scalar_set_b32(&secret, keypair->secret, NULL);
    secp256k1_scalar_set_b32(&hiding, nonce->hiding, NULL);
    secp256k1_scalar_set_b32(&binding, nonce->binding, NULL);

    /* z_i = hiding_i + binding_i * rho_i + lambda_i * s_i * c */
    secp256k1_scalar_mul(&term1, &binding, my_rho_i);
    secp256k1_scalar_mul(&term2, &lambda_i, &secret);
    secp256k1_scalar_mul(&term2, &term2, &c);
    secp256k1_scalar_add(&sig_share, &hiding, &term1);
    secp256k1_scalar_add(&sig_share, &sig_share, &term2);

    if (is_group_commitment_odd) {
        /* z_i' = -z_i + 2 * lambda_i * s_i * c */
        secp256k1_scalar adj;
        secp256k1_scalar_set_int(&adj, 2);
        secp256k1_scalar_mul(&adj, &adj, &lambda_i);
        secp256k1_scalar_mul(&adj, &adj, &secret);
        secp256k1_scalar_mul(&adj, &adj, &c);
        secp256k1_scalar_negate(&sig_share, &sig_share);
        secp256k1_scalar_add(&sig_share, &sig_share, &adj);
    }

    secp256k1_scalar_get_b32(response->response, &sig_share);
    response->index = keypair->public_keys.index;

    return 1;
}

SECP256K1_API int secp256k1_frost_pubkey_from_keypair(secp256k1_frost_pubkey *pubkey,
                                                      const secp256k1_frost_keypair *keypair) {
    if (pubkey == NULL || keypair == NULL) {
        return 0;
    }
    pubkey->index = keypair->public_keys.index;
    pubkey->max_participants = keypair->public_keys.max_participants;
    memcpy(&pubkey->public_key, &keypair->public_keys.public_key, 64);
    memcpy(&pubkey->group_public_key, &keypair->public_keys.group_public_key, 64);
    return 1;
}

SECP256K1_API int secp256k1_frost_sign(
        secp256k1_frost_signature_share *signature_share,
        const unsigned char *msg32,
        uint32_t num_signers,
        const secp256k1_frost_keypair *keypair,
        secp256k1_frost_nonce *nonce,
        secp256k1_frost_nonce_commitment *signing_commitments) {

    secp256k1_frost_binding_factors binding_factors;

    if (signature_share == NULL || msg32 == NULL || keypair == NULL || nonce == NULL || signing_commitments == NULL) {
        return 0;
    }
    if (num_signers == 0 || num_signers > keypair->public_keys.max_participants) {
        return 0;
    }

    if (nonce->used == 1) {
        return 0;
    }
    binding_factors.num_binding_factors = num_signers;
    binding_factors.binding_factors = (secp256k1_scalar *)
            checked_malloc(&default_error_callback, num_signers * sizeof(secp256k1_scalar));
    binding_factors.participant_indexes = (uint32_t *)
            checked_malloc(&default_error_callback, num_signers * sizeof(uint32_t));
    binding_factors.binding_factors_inputs =
            (unsigned char **)
                    checked_malloc(&default_error_callback, num_signers * sizeof(unsigned char *));

    /* Compute the binding factor(s) */
    if (compute_binding_factors(&binding_factors, msg32, 32, num_signers, signing_commitments) == 0) {
        return 0;
    }

    /* Sign the message */
    if (secp256k1_frost_sign_internal(signature_share, msg32, num_signers,
                                      keypair, nonce, signing_commitments,
                                      &binding_factors) == 0) {
        return 0;
    }

    /* Mark nonce as used */
    /* TODO: remove side effect on nonce */
    nonce->used = 1;

    /* Free all allocated vars */
    free_binding_factors(&binding_factors); /*FIXME: also the allocated unsigned char *  to be freed */

    return 1;
}

static SECP256K1_WARN_UNUSED_RESULT int check_commitment_and_response_integrity(
        const secp256k1_frost_nonce_commitment *commitments,
        const secp256k1_frost_signature_share *signature_shares,
        uint32_t num_signers) {
    uint32_t cmt_index, shr_index, cmt_found;
    cmt_found = 0;

    for (shr_index = 0; shr_index < num_signers; shr_index++) {
        cmt_found = 0;
        for (cmt_index = 0; cmt_index < num_signers; cmt_index++) {
            if (signature_shares[shr_index].index == commitments[cmt_index].index) {
                cmt_found = 1;
                break;
            }
        }
        if (cmt_found == 0) {
            return 0;
        }
    }
    return 1;
}

static SECP256K1_WARN_UNUSED_RESULT int is_signature_response_valid(const secp256k1_context *ctx,
                                                                    const secp256k1_frost_signature_share *response,
                                                                    const secp256k1_gej *pubkey,
                                                                    const secp256k1_scalar *lambda_i,
                                                                    const secp256k1_gej *commitment,
                                                                    const secp256k1_scalar *challenge) {
    secp256k1_gej lhs, rhs, partial;
    secp256k1_scalar cl, resp;

    secp256k1_scalar_set_b32(&resp, response->response, NULL);
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &lhs, &resp);
    secp256k1_scalar_mul(&cl, challenge, lambda_i);
    secp256k1_gej_mul_scalar(&partial, pubkey, &cl);

    secp256k1_gej_add_var(&rhs, commitment, &partial, NULL);

    return secp256k1_gej_eq(&lhs, &rhs);
}

static SECP256K1_WARN_UNUSED_RESULT int verify_signature_share(const secp256k1_context *ctx,
        /* in */ const secp256k1_frost_signature_share *signature_share,
                                                               const secp256k1_scalar *challenge,
                                                               const secp256k1_frost_binding_factors *binding_factors,
                                                               const secp256k1_frost_nonce_commitment *commitments,
                                                               const secp256k1_frost_pubkey *public_keys,
                                                               int is_group_commitment_odd,
                                                               uint32_t num_signers) {
    const secp256k1_frost_nonce_commitment *matching_commitment = NULL;
    secp256k1_gej signer_pubkey;
    secp256k1_gej partial, commitment_i, hiding_cmt, binding_cmt;
    secp256k1_scalar lambda_i;
    secp256k1_scalar *matching_rho_i;
    uint32_t index;
    int found;

    /* Get the binding factor by participant index of the signature share */
    found = 0;
    for (index = 0; index < binding_factors->num_binding_factors; index++) {
        if (binding_factors->participant_indexes[index] == signature_share->index) {
            matching_rho_i = &(binding_factors->binding_factors[index]);
            found = 1;
            break;
        }
    }
    if (found == 0) {
        /* No matching binding factors for this response */
        return 0;
    }

    /* Compute Lagrange coefficient */
    if (derive_interpolating_value(&lambda_i,
                                   signature_share->index, num_signers,
                                   binding_factors->participant_indexes) == 0) {
        return 0;
    }

    /* Retrieve signing commitment by participant index  */
    found = 0;
    for (index = 0; index < num_signers; index++) {
        if (commitments[index].index == signature_share->index) {
            matching_commitment = &(commitments[index]);
            found = 1;
            break;
        }
    }
    if (found == 0) {
        /* No matching commitment for response */
        return 0;
    }

    /* Retrieve signer pubkey by participant index  */
    found = 0;
    for (index = 0; index < num_signers; index++) {
        if (public_keys[index].index == matching_commitment->index) {
            deserialize_point(&signer_pubkey, public_keys[index].public_key);
            found = 1;
            break;
        }
    }
    if (found == 0) {
        /* Commitment does not have a matching signer public key */
        return 0;
    }

    /* Compute the commitment share */
    deserialize_point(&hiding_cmt, matching_commitment->hiding);
    deserialize_point(&binding_cmt, matching_commitment->binding);
    secp256k1_gej_mul_scalar(&partial, &binding_cmt, matching_rho_i);
    secp256k1_gej_add_var(&commitment_i, &hiding_cmt, &partial, NULL);

    if (is_group_commitment_odd == 1) {
        secp256k1_gej_neg(&commitment_i, &commitment_i);
    }

    if (is_signature_response_valid(ctx, signature_share, &signer_pubkey,
                                    &lambda_i, &commitment_i, challenge) == 0) {
        return 0;
    }
    return 1;
}

SECP256K1_API int secp256k1_frost_aggregate(const secp256k1_context *ctx,
        /* out: */ unsigned char *sig64,
                                            const unsigned char *msg32,
                                            const secp256k1_frost_keypair *keypair,
                                            const secp256k1_frost_pubkey *public_keys,
                                            secp256k1_frost_nonce_commitment *commitments,
                                            const secp256k1_frost_signature_share *signature_shares,
                                            uint32_t num_signers) {
    secp256k1_frost_binding_factors binding_factors;
    secp256k1_frost_signature aggregated_signature;
    secp256k1_scalar challenge;
    secp256k1_gej group_pubkey;
    int is_group_commitment_odd;
    uint32_t index;

    if (ctx == NULL || sig64 == NULL || msg32 == NULL || keypair == NULL || public_keys == NULL ||
        commitments == NULL || signature_shares == NULL) {
        return 0;
    }

    if (num_signers > keypair->public_keys.max_participants) {
        return 0;
    }

    if (check_commitment_and_response_integrity(commitments, signature_shares, num_signers) == 0) {
        return 0;
    }

    binding_factors.num_binding_factors = num_signers;
    binding_factors.binding_factors = (secp256k1_scalar *)
            checked_malloc(&default_error_callback, num_signers * sizeof(secp256k1_scalar));
    binding_factors.participant_indexes = (uint32_t *)
            checked_malloc(&default_error_callback, num_signers * sizeof(uint32_t));
    binding_factors.binding_factors_inputs =
            (unsigned char **)
                    checked_malloc(&default_error_callback, num_signers * sizeof(unsigned char *));

    /* Compute the binding factor(s) */
    if (compute_binding_factors(&binding_factors, msg32, 32, num_signers, commitments) == 0) {
        free_binding_factors(&binding_factors);
        return 0;
    }

    /* Compute the group commitment */
    if (compute_group_commitment(&(aggregated_signature.r), &is_group_commitment_odd,
                                 num_signers, &binding_factors, commitments) == 0) {
        free_binding_factors(&binding_factors);
        return 0;
    }

    /* Compute message-based challenge */
    deserialize_point(&group_pubkey, keypair->public_keys.group_public_key);
    compute_challenge(&challenge, msg32, 32, &group_pubkey, &(aggregated_signature.r));

    /* check the validity of each participant's response */
    for (index = 0; index < num_signers; index++) {
        if (verify_signature_share(ctx,
                                   &signature_shares[index],
                                   &challenge,
                                   &binding_factors,
                                   commitments,
                                   public_keys,
                                   is_group_commitment_odd,
                                   num_signers) == 0) {
            free_binding_factors(&binding_factors);
            return 0;
        }

    }

    /* Aggregate signature shares */
    secp256k1_scalar_set_int(&(aggregated_signature.z), 0);

    for (index = 0; index < num_signers; index++) {
        secp256k1_scalar part_response;
        secp256k1_scalar_set_b32(&part_response, signature_shares[index].response, NULL);
        secp256k1_scalar_add(&(aggregated_signature.z), &(aggregated_signature.z), &part_response);
    }

    if (is_group_commitment_odd) {
        secp256k1_gej_neg(&(aggregated_signature.r), &(aggregated_signature.r));
    }

    /* Serialize aggregated signature */
    serialize_frost_signature(sig64, &aggregated_signature);

    /* Free all allocated vars */
    free_binding_factors(&binding_factors);

    return 1;
}

/* TODO: this function can be removed, because aggregated signatures can be
 * already verified using Schnorr verification */
SECP256K1_API SECP256K1_WARN_UNUSED_RESULT int secp256k1_frost_verify(
        const secp256k1_context *ctx,
        const unsigned char *sig64,
        const unsigned char *msg32,
        const secp256k1_frost_pubkey *pubkey) {

    secp256k1_scalar challenge;
    secp256k1_gej term1, rhs, term2, term2_neg, group_pubkey;
    secp256k1_frost_signature aggregated_signature;

    if (ctx == NULL || sig64 == NULL || msg32 == NULL || pubkey == NULL) {
        return 0;
    }

    /* Deserialize frost signature */
    if (deserialize_frost_signature(&aggregated_signature, sig64) == 0) {
        return 0;
    }

    /* Compute message-based challenge */
    deserialize_point(&group_pubkey, pubkey->group_public_key);
    compute_challenge(&challenge, msg32, 32, &group_pubkey, &(aggregated_signature.r));

    /* sig.r ?= (G * sig.z) - (pubkey * challenge) */
    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &term1, &(aggregated_signature.z));
    secp256k1_gej_mul_scalar(&term2, &group_pubkey, &challenge);
    secp256k1_gej_neg(&term2_neg, &term2);
    secp256k1_gej_add_var(&rhs, &term1, &term2_neg, NULL);

    return secp256k1_gej_eq(&(aggregated_signature.r), &rhs);
}

#endif /* SECP256K1_MODULE_FROST_MAIN_H */
