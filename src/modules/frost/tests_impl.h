/***********************************************************************
 * Copyright (c) 2023 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_FROST_TESTS_H
#define SECP256K1_MODULE_FROST_TESTS_H

#include "../../../include/secp256k1_frost.h"


void test_secp256k1_gej_eq_case_1(void) {
    secp256k1_gej a, b;
    secp256k1_ge a_ge, b_ge;
    secp256k1_fe x1_fe, y1_fe, x2_fe, y2_fe;
    secp256k1_ge_clear(&a_ge);
    secp256k1_ge_clear(&b_ge);
    secp256k1_fe_set_int(&x1_fe, 1);
    secp256k1_fe_set_int(&y1_fe, 1);
    secp256k1_fe_set_int(&x2_fe, 1);
    secp256k1_fe_set_int(&y2_fe, 1);
    secp256k1_ge_set_xy(&a_ge, &x1_fe, &y1_fe);
    secp256k1_ge_set_xy(&b_ge, &x2_fe, &y2_fe);
    secp256k1_gej_set_ge(&a, &a_ge);
    secp256k1_gej_set_ge(&b, &b_ge);
    CHECK(secp256k1_gej_eq(&a, &b) == 1);
}

void test_secp256k1_gej_eq_case_2(void) {
    secp256k1_gej a, b;
    secp256k1_ge a_ge, b_ge;
    secp256k1_fe x1_fe, y1_fe, x2_fe, y2_fe;
    secp256k1_ge_clear(&a_ge);
    secp256k1_ge_clear(&b_ge);
    secp256k1_fe_set_int(&x1_fe, 1);
    secp256k1_fe_set_int(&y1_fe, 1);
    secp256k1_fe_set_int(&x2_fe, 1);
    secp256k1_fe_set_int(&y2_fe, 2);
    secp256k1_ge_set_xy(&a_ge, &x1_fe, &y1_fe);
    secp256k1_ge_set_xy(&b_ge, &x2_fe, &y2_fe);
    secp256k1_gej_set_ge(&a, &a_ge);
    secp256k1_gej_set_ge(&b, &b_ge);
    CHECK(secp256k1_gej_eq(&a, &b) == 0);
}

void test_secp256k1_gej_eq_case_3(void) {
    secp256k1_gej a, b;
    secp256k1_ge a_ge, b_ge;
    secp256k1_fe x1_fe, y1_fe, x2_fe, y2_fe;
    secp256k1_ge_clear(&a_ge);
    secp256k1_ge_clear(&b_ge);
    secp256k1_fe_set_int(&x1_fe, 1);
    secp256k1_fe_set_int(&y1_fe, 1);
    secp256k1_fe_set_int(&x2_fe, 2);
    secp256k1_fe_set_int(&y2_fe, 1);
    secp256k1_ge_set_xy(&a_ge, &x1_fe, &y1_fe);
    secp256k1_ge_set_xy(&b_ge, &x2_fe, &y2_fe);
    secp256k1_gej_set_ge(&a, &a_ge);
    secp256k1_gej_set_ge(&b, &b_ge);
    CHECK(secp256k1_gej_eq(&a, &b) == 0);
}

void test_secp256k1_gej_eq_case_4(void) {
    secp256k1_gej a, b;
    secp256k1_ge a_ge, b_ge;
    secp256k1_fe x1_fe, y1_fe, x2_fe, y2_fe;
    secp256k1_ge_clear(&a_ge);
    secp256k1_ge_clear(&b_ge);
    secp256k1_fe_set_int(&x1_fe, 1);
    secp256k1_fe_set_int(&y1_fe, 1);
    secp256k1_fe_set_int(&x2_fe, 2);
    secp256k1_fe_set_int(&y2_fe, 2);
    secp256k1_ge_set_xy(&a_ge, &x1_fe, &y1_fe);
    secp256k1_ge_set_xy(&b_ge, &x2_fe, &y2_fe);
    secp256k1_gej_set_ge(&a, &a_ge);
    secp256k1_gej_set_ge(&b, &b_ge);
    CHECK(secp256k1_gej_eq(&a, &b) == 0);
}

void test_nonce_generate_with_seed(void) {
    unsigned char buffer[32] = {0};
    unsigned char check[32] = {0};
    unsigned char seed[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    uint32_t index;
    int init;
    secp256k1_frost_keypair keypair;
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    nonce_generate(buffer, &keypair, seed);
    init = 0;
    for (index = 0; index < 32; index++) {
        if (buffer[index] != check[index]) {
            init = 1;
            break;
        }
    }
    CHECK(init == 1);
}

void test_nonce_generate_with_no_seed(void) {
    unsigned char buffer[32] = {0};
    unsigned char check[32] = {0};
    unsigned char *seed = NULL;
    uint32_t index;
    int init;
    secp256k1_frost_keypair keypair;
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    nonce_generate(buffer, &keypair, seed);
    init = 0;
    for (index = 0; index < 32; index++) {
        if (buffer[index] != check[index]) {
            init = 1;
            break;
        }
    }
    CHECK(init == 1);
}

/*
 * Try to create a new secp256k1_frost_nonce with null context.
 */
void test_secp256k1_frost_nonce_create_null_context(void) {
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_nonce *nonce;
    secp256k1_frost_keypair keypair;

    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    nonce = secp256k1_frost_nonce_create(NULL, &keypair, binding_seed, hiding_seed);
    CHECK(nonce == NULL);
}

/*
 * Try to create a new secp256k1_frost_nonce object with null keypair.
 */
void test_secp256k1_frost_nonce_create_null_keypair(void) {
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_context *sign_ctx;
    secp256k1_frost_nonce *nonce;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    nonce = secp256k1_frost_nonce_create(sign_ctx, NULL, binding_seed, hiding_seed);
    CHECK(nonce == NULL);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to create a new secp256k1_frost_nonce object with null binding_seed.
 */
void test_secp256k1_frost_nonce_create_null_binding_seed(void) {
    unsigned char hiding_seed[32] = {0};
    secp256k1_context *sign_ctx;
    secp256k1_frost_nonce *nonce;
    secp256k1_frost_keypair keypair;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    nonce = secp256k1_frost_nonce_create(sign_ctx, &keypair, NULL, hiding_seed);
    CHECK(nonce == NULL);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to create a new secp256k1_frost_nonce object with null hiding_seed.
 */
void test_secp256k1_frost_nonce_create_null_hiding_seed(void) {
    unsigned char binding_seed[32] = {0};
    secp256k1_context *sign_ctx;
    secp256k1_frost_nonce *nonce;
    secp256k1_frost_keypair keypair;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    nonce = secp256k1_frost_nonce_create(sign_ctx, &keypair, binding_seed, NULL);
    CHECK(nonce == NULL);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to destroy a null secp256k1_frost_nonce object.
 */
void test_secp256k1_frost_nonce_destroy_null_nonce(void) {
    secp256k1_frost_nonce_destroy(NULL);
}

/*
 * Try to create a new secp256k1_frost_nonce object.
 * Nonce is computed using a random seed passed as argument; if the same seed is provided, the same nonce is
 * generated.
 */
void test_secp256k1_frost_nonce_create_and_destroy(void) {
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_context *sign_ctx;
    secp256k1_frost_nonce *nonce;
    secp256k1_frost_keypair keypair;

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    /* keypair initialized to 0, because it is not computed using keygen functions */
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    keypair.public_keys.index = 27;
    nonce = secp256k1_frost_nonce_create(sign_ctx, &keypair, binding_seed, hiding_seed);

    CHECK(nonce != NULL);
    /* Check if index has been propagated to commitments */
    CHECK(nonce->commitments.index == 27);
    /* We use the same seed for binding and hiding: expected nonce to be the same */
    CHECK(memcmp(nonce->binding, nonce->hiding, 32) == 0);
    /* We use the same seed for binding and hiding: expected commitments to be the same */
    CHECK(memcmp(nonce->commitments.binding, nonce->commitments.hiding, 64) == 0);

    secp256k1_frost_nonce_destroy(nonce);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to create a new secp256k1_frost_nonce object.
 * Nonce is computed using a random seed passed as argument;
 * if different seeds are provided, different nonces are generated.
 */
void test_secp256k1_frost_nonce_create_with_different_nonce(void) {
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {1};
    secp256k1_context *sign_ctx;
    secp256k1_frost_nonce *nonce;
    secp256k1_frost_keypair keypair;

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    /* keypair initialized to 0, because it is not computed using keygen functions */
    memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
    keypair.public_keys.index = 27;
    nonce = secp256k1_frost_nonce_create(sign_ctx, &keypair, binding_seed, hiding_seed);

    CHECK(nonce != NULL);
    CHECK(nonce->commitments.index == 27);
    /* We use the same seed for binding and hiding: expected nonce to be different */
    CHECK(memcmp(nonce->binding, nonce->hiding, 32) != 0);
    /* We use the same seed for binding and hiding: expected commitments to be different */
    CHECK(memcmp(nonce->commitments.binding, nonce->commitments.hiding, 64) != 0);

    secp256k1_frost_nonce_destroy(nonce);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to create a new secp256k1_frost_vss_commitments object.
 * The object will not be initialized.
 * The creation method only allocate memory for coefficient commitments.
 */
void test_secp256k1_frost_vss_commitments_create_and_destroy(void) {
    secp256k1_frost_vss_commitments *vss;
    const uint32_t threshold = 30;
    vss = secp256k1_frost_vss_commitments_create(threshold);
    CHECK(vss != NULL);
    CHECK(vss->num_coefficients == threshold);
    secp256k1_frost_vss_commitments_destroy(vss);
}

/*
 * Do not create if threshold is less than 1.
 */
void test_secp256k1_frost_vss_commitments_create_null_when_threshold_lt_1(void) {
    secp256k1_frost_vss_commitments *vss;
    const uint32_t threshold = 0;
    vss = secp256k1_frost_vss_commitments_create(threshold);
    CHECK(vss == NULL);
}

/*
 * Try to create a new secp256k1_frost_keypair object.
 * The object will not be initialized (a keygen is needed for this purpose).
 * The creation method only assigns the participant index.
 */
void test_secp256k1_frost_keypair_create_and_destroy(void) {
    secp256k1_frost_keypair *keypair;
    uint32_t participant_index = 30;

    keypair = secp256k1_frost_keypair_create(participant_index);

    CHECK(keypair != NULL);
    CHECK(keypair->public_keys.index == participant_index);

    secp256k1_frost_keypair_destroy(keypair);
}

/*
 * Try to destroy a null secp256k1_frost_keypair object.
 */
void test_secp256k1_frost_keypair_destroy_null_keypair(void) {
    secp256k1_frost_keypair_destroy(NULL);
}

/*
 * Try to execute the first step of DKG.
 * Expect error when participants < 1
 */
void test_secp256k1_frost_keygen_begin_invalid_participants(void) {
    int result;
    const unsigned char context[4] = "test";
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 0, /* threshold */ 2,
                                              1, context, 4);

    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to execute the first step of DKG.
 * Expect error when threshold < 1
 */
void test_secp256k1_frost_keygen_begin_invalid_threshold(void) {
    int result;
    const unsigned char context[4] = "test";
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(1);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 2, /* threshold */ 0,
                                              1, context, 4);

    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to execute the first step of DKG.
 * Expect error when threshold > participants
 */
void test_secp256k1_frost_keygen_begin_threshold_gt_participants(void) {
    int result;
    const unsigned char context[4] = "test";
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    const uint32_t threshold = 3;

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(threshold);

    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 2, threshold,
                                              1, context, 4);

    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to execute the first step of DKG, with null context.
 */
void test_secp256k1_frost_keygen_begin_null_secp_context(void) {
    secp256k1_context *sign_ctx = NULL;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    int result;
    const unsigned char context[4] = "test";

    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, context, 4);
    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to execute the first step of DKG, with null commitment.
 */
void test_secp256k1_frost_keygen_begin_null_commitment(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment = NULL;
    secp256k1_frost_keygen_secret_share shares[3];
    int result;
    const unsigned char context[4] = "test";

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, context, 4);
    CHECK(result == 0);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to execute the first step of DKG, with null shares.
 */
void test_secp256k1_frost_keygen_begin_null_shares(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share *shares = NULL;
    int result;
    const unsigned char context[4] = "test";

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, context, 4);
    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to execute the first step of DKG with null context.
 */
void test_secp256k1_frost_keygen_begin_null_context(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    int result;

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, NULL, 0);
    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to execute the first step of DKG.
 */
void test_secp256k1_frost_keygen_begin(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    int result;
    const unsigned char context[4] = "test";

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, context, 4);
    CHECK(result == 1);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to evaluate the commitments produced by the first step of DKG.
 */
void test_secp256k1_frost_keygen_validate(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    int result;
    const unsigned char context[4] = "test";

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, context, 4);
    CHECK(result == 1);

    result = secp256k1_frost_keygen_dkg_commitment_validate(
            sign_ctx,
            dkg_commitment,
            context, 4);

    CHECK(result == 1);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_keygen_validate_null_secp_context(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    int result;
    const unsigned char context[4] = "test";

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, context, 4);
    CHECK(result == 1);

    result = secp256k1_frost_keygen_dkg_commitment_validate(
            NULL,
            dkg_commitment,
            context, 4);

    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_keygen_validate_null_commitment(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    int result;
    const unsigned char context[4] = "test";

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, context, 4);
    CHECK(result == 1);

    result = secp256k1_frost_keygen_dkg_commitment_validate(
            sign_ctx,
            NULL,
            context, 4);

    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_keygen_validate_null_context(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    int result;
    const unsigned char context[4] = "test";

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, context, 4);
    CHECK(result == 1);

    result = secp256k1_frost_keygen_dkg_commitment_validate(
            sign_ctx,
            dkg_commitment,
            NULL, 4);

    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Check whether keygen_validate returns 0 on invalid commitments.
 */
void test_secp256k1_frost_keygen_validate_invalid_secret_commitment(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    secp256k1_gej _invalidPoint;
    int result;
    const unsigned char context[4] = "test";
    const uint32_t threshold = 2;

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(threshold);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ threshold,
            /* participant_index */ 1, context, 4);
    CHECK(result == 1);

    /* now, set the first commitments to be invalid */
    secp256k1_gej_clear(&_invalidPoint);
    serialize_point(&_invalidPoint, dkg_commitment->coefficient_commitments[0].data);

    /* now, ensure that this dkg commitment is marked as invalid */
    result = secp256k1_frost_keygen_dkg_commitment_validate(
            sign_ctx,
            dkg_commitment,
            context, 4);

    CHECK(result == 0);
    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Check whether keygen_validate returns 0 when a different context is used for validation.
 */
void test_secp256k1_frost_keygen_validate_invalid_context(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dkg_commitment;
    secp256k1_frost_keygen_secret_share shares[3];
    int result;
    const unsigned char context[4] = "test";
    const unsigned char invalid_context[7] = "invalid";

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = secp256k1_frost_vss_commitments_create(2);
    result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment, shares,
            /* num_participants */ 3,
            /* threshold */ 2,
            /* participant_index */ 1, context, 4);
    CHECK(result == 1);

    /* calling validate with a different context */
    result = secp256k1_frost_keygen_dkg_commitment_validate(
            sign_ctx,
            dkg_commitment,
            invalid_context, sizeof(invalid_context));
    CHECK(result == 0);

    secp256k1_frost_vss_commitments_destroy(dkg_commitment);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to finalize the DKG. If no error occurs, 1 is returned.
 */
void test_secp256k1_frost_keygen_finalize(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    secp256k1_frost_keygen_secret_share shares_per_participant[3][3];
    int i_share_per_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypair;
    uint32_t index;
    const unsigned char context[4] = "test";
    const uint32_t threshold = 2;

    /* Step 1. initialization */
    num_participants = 3;
    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    for (index = 0; index < num_participants; index++) {
        i_share_per_participant[index] = 0;
        dkg_commitment[index] = secp256k1_frost_vss_commitments_create(threshold);
    }
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* Step 2. keygen begin and validate for each participant */
    for (index = 0; index < num_participants; index++) {
        uint32_t share_index;
        result = secp256k1_frost_keygen_dkg_begin(sign_ctx,
                                                  dkg_commitment[index],
                                                  shares_by_participant,
                /* num_participants */ 3, threshold,
                                                  index + 1, context, 4);
        CHECK(result == 1);

        result = secp256k1_frost_keygen_dkg_commitment_validate(sign_ctx, dkg_commitment[index], context, 4);
        CHECK(result == 1);

        /* Step 3. dispatching shares for single participant */
        for (share_index = 0; share_index < 3; share_index++) {
            uint32_t spi;
            spi = shares_by_participant[share_index].receiver_index - 1;
            shares_per_participant[spi][i_share_per_participant[spi]] =
                    shares_by_participant[share_index];
            i_share_per_participant[spi]++;
        }
    }

    /* Step 4. keygen finalize for each participant */
    for (index = 0; index < num_participants; index++) {
        result = secp256k1_frost_keygen_dkg_finalize(sign_ctx, &keypair, index + 1, 3,
                                                     shares_per_participant[index],
                                                     dkg_commitment);
        CHECK(result == 1);
    }

    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_vss_commitments_destroy(dkg_commitment[index]);
    }
    secp256k1_context_destroy(sign_ctx);
    free(dkg_commitment);
}

void test_secp256k1_frost_keygen_finalize_null_secp_context(void) {
    const secp256k1_context *sign_ctx = NULL;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_per_participant;
    int result;
    secp256k1_frost_keypair keypair;
    const uint32_t num_participants = 3;

    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    memset(&shares_per_participant, 0, sizeof(secp256k1_frost_keygen_secret_share));
    result = secp256k1_frost_keygen_dkg_finalize(sign_ctx, &keypair, 1, num_participants,
                                                 &shares_per_participant,
                                                 dkg_commitment);
    CHECK(result == 0);
    free(dkg_commitment);
}

void test_secp256k1_frost_keygen_finalize_null_keypair(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_per_participant;
    int result;
    const uint32_t num_participants = 3;
    secp256k1_frost_keypair *keypair = NULL;

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    memset(&shares_per_participant, 0, sizeof(secp256k1_frost_keygen_secret_share));
    result = secp256k1_frost_keygen_dkg_finalize(sign_ctx, keypair, 1, num_participants,
                                                 &shares_per_participant,
                                                 dkg_commitment);
    CHECK(result == 0);
    secp256k1_context_destroy(sign_ctx);
    free(dkg_commitment);
}

void test_secp256k1_frost_keygen_finalize_null_shares(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share *shares_per_participant = NULL;
    int result;
    const uint32_t num_participants = 3;
    secp256k1_frost_keypair keypair;

    /* Step 1. initialization */
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    result = secp256k1_frost_keygen_dkg_finalize(sign_ctx, &keypair, 1, num_participants,
                                                 shares_per_participant,
                                                 dkg_commitment);
    CHECK(result == 0);
    secp256k1_context_destroy(sign_ctx);
    free(dkg_commitment);
}

void test_secp256k1_frost_keygen_finalize_null_commitments(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment = NULL;
    secp256k1_frost_keygen_secret_share shares_per_participant;
    int result;
    const uint32_t num_participants = 3;
    secp256k1_frost_keypair keypair;

    /* Step 1. initialization */
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    memset(&shares_per_participant, 0, sizeof(secp256k1_frost_keygen_secret_share));
    result = secp256k1_frost_keygen_dkg_finalize(sign_ctx, &keypair, 1, num_participants,
                                                 &shares_per_participant,
                                                 dkg_commitment);
    CHECK(result == 0);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Verify that the keypairs can successfully reconstruct the group public key.
 */
void test_secp256k1_frost_keygen_finalize_is_valid(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    secp256k1_frost_keygen_secret_share shares_per_participant[3][3];
    int i_share_per_participant[3];
    uint32_t signer_indexes[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];
    uint32_t index;
    const unsigned char context[4] = "test";

    /* Step 1. initialization */
    num_participants = 3;
    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    for (index = 0; index < num_participants; index++) {
        i_share_per_participant[index] = 0;
        signer_indexes[index] = index + 1;
        dkg_commitment[index] = secp256k1_frost_vss_commitments_create(2);
    }
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* Step 2. keygen begin and validate for each participant */
    for (index = 0; index < num_participants; index++) {
        uint32_t share_index;
        result = secp256k1_frost_keygen_dkg_begin(sign_ctx,
                                                  dkg_commitment[index],
                                                  shares_by_participant,
                /* num_participants */ 3, /* threshold */ 2,
                                                  index + 1, context, 4);
        CHECK(result == 1);

        result = secp256k1_frost_keygen_dkg_commitment_validate(sign_ctx, dkg_commitment[index], context, 4);
        CHECK(result == 1);

        /* Step 3. dispatching shares for single participant */
        for (share_index = 0; share_index < 3; share_index++) {
            uint32_t spi;
            spi = shares_by_participant[share_index].receiver_index - 1;
            shares_per_participant[spi][i_share_per_participant[spi]] =
                    shares_by_participant[share_index];
            i_share_per_participant[spi]++;
        }
    }

    /* Step 4. keygen finalize for each participant */
    for (index = 0; index < num_participants; index++) {
        result = secp256k1_frost_keygen_dkg_finalize(sign_ctx, &(keypairs[index]), index + 1, 3,
                                                     shares_per_participant[index],
                                                     dkg_commitment);
        CHECK(result == 1);
    }

    /* Ensure we can reconstruct the secret, given all the secret keys */
    {
        secp256k1_scalar output;
        secp256k1_gej received_public, group_pubkey;
        int is_equal;

        secp256k1_scalar_set_int(&output, 0);
        for (index = 0; index < num_participants; index++) {
            secp256k1_scalar lambda, output_partial, secret;

            result = derive_interpolating_value(&lambda, keypairs[index].public_keys.index,
                                                num_participants, signer_indexes);
            CHECK(result == 1);

            secp256k1_scalar_set_b32(&secret, keypairs[index].secret, NULL);
            secp256k1_scalar_mul(&output_partial, &secret, &lambda);
            secp256k1_scalar_add(&output, &output, &output_partial);
        }
        secp256k1_ecmult_gen(&sign_ctx->ecmult_gen_ctx, &received_public, &output);

        deserialize_point(&group_pubkey, keypairs[0].public_keys.group_public_key);
        /* ensure that the secret terms interpolate to the correct public key */
        is_equal = secp256k1_gej_eq(&received_public, &group_pubkey);
        CHECK(is_equal == 1);
    }

    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_vss_commitments_destroy(dkg_commitment[index]);
    }
    secp256k1_context_destroy(sign_ctx);
    free(dkg_commitment);
}

/*
 * When a different participant index is provided to keygen_finalize,
 * it should return no error, but the keygen index is modified accordingly.
 */
void test_secp256k1_frost_keygen_finalize_different_participant_index(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    secp256k1_frost_keygen_secret_share shares_per_participant[3][3];
    int i_share_per_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypair;
    uint32_t index;
    const unsigned char context[4] = "test";

    /* Step 1. initialization */
    num_participants = 3;
    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    for (index = 0; index < num_participants; index++) {
        i_share_per_participant[index] = 0;
        dkg_commitment[index] = secp256k1_frost_vss_commitments_create(2);
    }
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* Step 2. keygen begin and validate for each participant */
    for (index = 0; index < num_participants; index++) {
        uint32_t share_index;
        result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment[index], shares_by_participant,
                                                  3, 2, index + 1, context, 4);
        CHECK(result == 1);

        result = secp256k1_frost_keygen_dkg_commitment_validate(sign_ctx, dkg_commitment[index], context, 4);
        CHECK(result == 1);

        /* Step 3. dispatching shares for single participant */
        for (share_index = 0; share_index < 3; share_index++) {
            uint32_t spi;
            spi = shares_by_participant[share_index].receiver_index - 1;
            shares_per_participant[spi][i_share_per_participant[spi]] = shares_by_participant[share_index];
            i_share_per_participant[spi]++;
        }
    }

    /* Step 4. keygen finalize for each participant */
    for (index = 0; index < num_participants; index++) {
        /* Testing the following line: when a different participant index, result == 0 is expected. */
        result = secp256k1_frost_keygen_dkg_finalize(sign_ctx, &keypair, ((index + 2) % num_participants),
                                                     3, shares_per_participant[index], dkg_commitment);
        CHECK(result == 1);
        CHECK(keypair.public_keys.index == ((index + 2) % num_participants));
    }

    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_vss_commitments_destroy(dkg_commitment[index]);
    }
    secp256k1_context_destroy(sign_ctx);
    free(dkg_commitment);
}

/*
 * Try to finalize the keygen with invalid commitments; expected 0 (error code).
 */
void test_secp256k1_frost_keygen_finalize_invalid_commitments(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    secp256k1_frost_keygen_secret_share shares_per_participant[3][3];
    int i_share_per_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypair;
    uint32_t index;
    const unsigned char context[4] = "test";
    secp256k1_gej _invalidPoint;

    /* Step 1. initialization */
    num_participants = 3;
    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    for (index = 0; index < num_participants; index++) {
        i_share_per_participant[index] = 0;
        dkg_commitment[index] = secp256k1_frost_vss_commitments_create(2);
    }
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* Step 2. keygen begin and validate for each participant */
    for (index = 0; index < num_participants; index++) {
        uint32_t share_index;
        result = secp256k1_frost_keygen_dkg_begin(sign_ctx, dkg_commitment[index], shares_by_participant,
                                                  3, 2, index + 1, context, 4);
        CHECK(result == 1);

        result = secp256k1_frost_keygen_dkg_commitment_validate(sign_ctx, dkg_commitment[index], context, 4);
        CHECK(result == 1);

        /* Step 3. dispatching shares for single participant */
        for (share_index = 0; share_index < 3; share_index++) {
            uint32_t spi;
            spi = shares_by_participant[share_index].receiver_index - 1;
            shares_per_participant[spi][i_share_per_participant[spi]] = shares_by_participant[share_index];
            i_share_per_participant[spi]++;
        }
    }

    /* now, set the first commitments to be invalid */
    secp256k1_gej_clear(&_invalidPoint);
    serialize_point(&_invalidPoint, dkg_commitment[0]->coefficient_commitments[0].data);

    /* Step 4. keygen finalize for each participant */
    for (index = 0; index < num_participants; index++) {
        /* Testing the following line: invalidating the commitments. */
        result = secp256k1_frost_keygen_dkg_finalize(sign_ctx, &keypair, index + 1,
                                                     3, shares_per_participant[index], dkg_commitment);
        CHECK(result == 0);
    }

    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_vss_commitments_destroy(dkg_commitment[index]);
    }
    secp256k1_context_destroy(sign_ctx);
    free(dkg_commitment);
}

/*
 * Test the signing_commitment_sort (quicksort) on a randomly sorted array.
 */
void test_quicksort_on_signing_commitment(void) {
    uint32_t i;
    secp256k1_frost_nonce_commitment cmt[5];
    for (i = 0; i < 5; i++) {
        cmt[i].index = (i * 3) % 5;
    }
    signing_commitment_sort(cmt, 0, 4);
    for (i = 0; i < 5; i++) {
        CHECK(cmt[i].index == i);
    }
}

/*
 * Test the signing_commitment_sort (quicksort) on an array with duplicates.
 */
void test_quicksort_on_signing_commitment_with_duplicates(void) {
    uint32_t i;
    secp256k1_frost_nonce_commitment cmt[5];
    for (i = 0; i < 5; i++) {
        cmt[i].index = (i * 3) % 5;
    }
    cmt[3].index = 0;

    signing_commitment_sort(cmt, 0, 4);

    for (i = 0; i < 5; i++) {
        uint32_t rhs;
        rhs = (uint32_t) (i > 0 ? i - 1 : i);
        CHECK(cmt[i].index == rhs);
    }
}

/*
 * Try to produce a signature_share. If no error occurs, 1 is returned.
 * This test does not verify the signature secp256k1_frost_keygen_secret_share.
 */
void test_secp256k1_frost_dkg_and_sign(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    secp256k1_frost_keygen_secret_share shares_per_participant[3][3];
    int i_share_per_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypair[3];
    uint32_t index;
    const unsigned char context[4] = "test";
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_share[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    for (index = 0; index < num_participants; index++) {
        i_share_per_participant[index] = 0;
        dkg_commitment[index] = secp256k1_frost_vss_commitments_create(2);
    }
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* Step 2. keygen begin and validate for each participant */
    for (index = 0; index < num_participants; index++) {
        uint32_t share_index;
        result = secp256k1_frost_keygen_dkg_begin(sign_ctx,
                                                  dkg_commitment[index],
                                                  shares_by_participant,
                /*num_participants*/  3, /* threshold */ 2,
                                                  index + 1, context, 4);
        CHECK(result == 1);

        result = secp256k1_frost_keygen_dkg_commitment_validate(sign_ctx, dkg_commitment[index], context, 4);
        CHECK(result == 1);

        /* Step 3. dispatching shares for single participant */
        for (share_index = 0; share_index < 3; share_index++) {
            uint32_t spi;
            spi = shares_by_participant[share_index].receiver_index - 1;
            shares_per_participant[spi][i_share_per_participant[spi]] =
                    shares_by_participant[share_index];
            i_share_per_participant[spi]++;
        }
    }

    /* Step 4. keygen finalize for each participant */
    for (index = 0; index < num_participants; index++) {
        result = secp256k1_frost_keygen_dkg_finalize(sign_ctx, &keypair[index], index + 1, 3,
                                                     shares_per_participant[index],
                                                     dkg_commitment);
        CHECK(result == 1);
    }

    /* Step 5: prepare signature commitments */
    for (index = 0; index < num_participants; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_ctx,
                                                     &keypair[index], binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 6: compute signature shares */
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_sign(&(signature_share[index]),
                             msg32, num_participants,
                             &keypair[index],
                             nonces[index],
                             signing_commitments);
    }

    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_vss_commitments_destroy(dkg_commitment[index]);
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_ctx);
    free(dkg_commitment);
}

void test_secp256k1_frost_keygen_with_single_dealer_null_secp_context(void) {
    secp256k1_context *sign_ctx = NULL;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];

    /* Step 1. initialization */
    num_participants = 3;
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                2);
    CHECK(result == 0);

    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
}

void test_secp256k1_frost_keygen_with_single_dealer_null_commitments(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments = NULL;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];

    /* Step 1. initialization */
    num_participants = 3;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                2);
    CHECK(result == 0);

    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_keygen_with_single_dealer_null_shares(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share *shares_by_participant = NULL;
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];

    /* Step 1. initialization */
    num_participants = 3;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                2);
    CHECK(result == 0);

    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_keygen_with_single_dealer_null_keypairs(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair *keypairs = NULL;

    /* Step 1. initialization */
    num_participants = 3;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                2);
    CHECK(result == 0);

    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Test whether a single dealer can produce keypairs.
 * Keygen using a single dealer is alternative to DKG.
 */
void test_secp256k1_frost_keygen_with_single_dealer(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];

    /* Step 1. initialization */
    num_participants = 3;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                2);
    CHECK(result == 1);

    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_keygen_with_single_dealer_invalid_participants(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];

    /* Step 1. initialization */
    num_participants = 0;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                2);
    CHECK(result == 0);

    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_keygen_with_single_dealer_invalid_threshold(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];

    /* Step 1. initialization */
    num_participants = 3;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                0);
    CHECK(result == 0);

    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_keygen_with_single_dealer_threshold_gt_participants(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];

    /* Step 1. initialization */
    num_participants = 3;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                num_participants + 1);
    CHECK(result == 0);

    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Test whether a single dealer can produce valid keypairs.
 */
void test_secp256k1_frost_keygen_with_single_dealer_is_valid(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];

    /* Step 1. initialization */
    num_participants = 3;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                2);
    CHECK(result == 1);

    /* Ensure we can reconstruct the secret, given all the secret keys */
    {
        secp256k1_scalar output;
        secp256k1_gej received_public, group_pubkey;
        int is_equal;
        uint32_t index;
        uint32_t signer_indexes[3];
        for (index = 0; index < num_participants; index++) {
            signer_indexes[index] = index + 1;
        }

        secp256k1_scalar_set_int(&output, 0);
        for (index = 0; index < num_participants; index++) {
            secp256k1_scalar lambda, output_partial, secret;

            result = derive_interpolating_value(&lambda, keypairs[index].public_keys.index,
                                                num_participants, signer_indexes);
            CHECK(result == 1);

            secp256k1_scalar_set_b32(&secret, keypairs[index].secret, NULL);
            secp256k1_scalar_mul(&output_partial, &secret, &lambda);
            secp256k1_scalar_add(&output, &output, &output_partial);
        }
        secp256k1_ecmult_gen(&sign_ctx->ecmult_gen_ctx, &received_public, &output);

        deserialize_point(&group_pubkey, keypairs[0].public_keys.group_public_key);
        /* ensure that the secret terms interpolate to the correct public key */
        is_equal = secp256k1_gej_eq(&received_public, &group_pubkey);
        CHECK(is_equal == 1);
    }

    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to produce a signature_share after keygen using single dealer.
 */
void test_secp256k1_frost_single_dealer_and_sign(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_share[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                2);
    CHECK(result == 1);

    /* Step 2: prepare signature commitments */
    for (index = 0; index < num_participants; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_sign(&(signature_share[index]),
                             msg32, num_participants,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_sign_null_signature_shares(void) {
    int result;
    uint32_t threshold_signers;
    secp256k1_frost_signature_share *signature_shares = NULL;
    secp256k1_frost_keypair keypairs;
    secp256k1_frost_nonce nonces;
    secp256k1_frost_nonce_commitment signing_commitments;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    threshold_signers = 2;

    memset(&keypairs, 0, sizeof(secp256k1_frost_keypair));
    memset(&nonces, 0, sizeof(secp256k1_frost_nonce));
    memset(&signing_commitments, 0, sizeof(secp256k1_frost_nonce_commitment));

    result = secp256k1_frost_sign(signature_shares,
                                  msg32, threshold_signers,
                                  &keypairs,
                                  &nonces,
                                  &signing_commitments);

    CHECK(result == 0);
}

void test_secp256k1_frost_sign_null_msg32(void) {
    int result;
    uint32_t threshold_signers;
    secp256k1_frost_signature_share signature_share;
    secp256k1_frost_keypair keypairs;
    secp256k1_frost_nonce nonces;
    secp256k1_frost_nonce_commitment signing_commitments;
    const unsigned char *msg32 = NULL;
    threshold_signers = 2;

    memset(&signature_share, 0, sizeof(secp256k1_frost_signature_share));
    memset(&keypairs, 0, sizeof(secp256k1_frost_keypair));
    memset(&nonces, 0, sizeof(secp256k1_frost_nonce));
    memset(&signing_commitments, 0, sizeof(secp256k1_frost_nonce_commitment));

    result = secp256k1_frost_sign(&signature_share,
                                  msg32, threshold_signers,
                                  &keypairs,
                                  &nonces,
                                  &signing_commitments);

    CHECK(result == 0);
}


void test_secp256k1_frost_sign_null_keypairs(void) {
    int result;
    uint32_t threshold_signers;
    secp256k1_frost_signature_share signature_share;
    secp256k1_frost_keypair *keypairs = NULL;
    secp256k1_frost_nonce nonces;
    secp256k1_frost_nonce_commitment signing_commitments;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    threshold_signers = 2;

    memset(&signature_share, 0, sizeof(secp256k1_frost_signature_share));
    memset(&nonces, 0, sizeof(secp256k1_frost_nonce));
    memset(&signing_commitments, 0, sizeof(secp256k1_frost_nonce_commitment));

    result = secp256k1_frost_sign(&signature_share,
                                  msg32, threshold_signers,
                                  keypairs,
                                  &nonces,
                                  &signing_commitments);

    CHECK(result == 0);
}

void test_secp256k1_frost_sign_null_nonces(void) {
    int result;
    uint32_t threshold_signers;
    secp256k1_frost_signature_share signature_share;
    secp256k1_frost_keypair keypairs;
    secp256k1_frost_nonce *nonces = NULL;
    secp256k1_frost_nonce_commitment signing_commitments;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    threshold_signers = 2;

    memset(&signature_share, 0, sizeof(secp256k1_frost_signature_share));
    memset(&keypairs, 0, sizeof(secp256k1_frost_keypair));
    memset(&signing_commitments, 0, sizeof(secp256k1_frost_nonce_commitment));

    result = secp256k1_frost_sign(&signature_share,
                                  msg32, threshold_signers,
                                  &keypairs,
                                  nonces,
                                  &signing_commitments);

    CHECK(result == 0);
}

void test_secp256k1_frost_sign_null_signing_commitments(void) {
    int result;
    uint32_t threshold_signers;
    secp256k1_frost_signature_share signature_share;
    secp256k1_frost_keypair keypairs;
    secp256k1_frost_nonce nonces;
    secp256k1_frost_nonce_commitment *signing_commitments = NULL;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    threshold_signers = 2;

    memset(&signature_share, 0, sizeof(secp256k1_frost_signature_share));
    memset(&keypairs, 0, sizeof(secp256k1_frost_keypair));
    memset(&nonces, 0, sizeof(secp256k1_frost_nonce));

    result = secp256k1_frost_sign(&signature_share,
                                  msg32, threshold_signers,
                                  &keypairs,
                                  &nonces,
                                  signing_commitments);

    CHECK(result == 0);
}

void test_secp256k1_frost_sign_num_signer_set_to_zero(void) {
    int result;
    uint32_t threshold_signers;
    secp256k1_frost_signature_share signature_share;
    secp256k1_frost_keypair keypairs;
    secp256k1_frost_nonce nonces;
    secp256k1_frost_nonce_commitment signing_commitments;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    threshold_signers = 0;

    memset(&signature_share, 0, sizeof(secp256k1_frost_signature_share));
    memset(&keypairs, 0, sizeof(secp256k1_frost_keypair));
    memset(&nonces, 0, sizeof(secp256k1_frost_nonce));
    memset(&signing_commitments, 0, sizeof(secp256k1_frost_nonce_commitment));

    result = secp256k1_frost_sign(&signature_share,
                                  msg32, threshold_signers,
                                  &keypairs,
                                  &nonces,
                                  &signing_commitments);

    CHECK(result == 0);
}

void test_secp256k1_frost_sign_more_participants_than_max_to_be_invalid(void) {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[3];
    secp256k1_frost_pubkey public_keys[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    threshold_signers = 2;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_verify_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_pubkey_from_keypair(&public_keys[index], &keypairs[index]);
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < threshold_signers; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < threshold_signers; index++) {
        result = secp256k1_frost_sign(&(signature_shares[index]),
                                      msg32, num_participants + 1,
                                      &keypairs[index],
                                      nonces[index],
                                      signing_commitments);
        CHECK(result == 0);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
}

/*
 * Try to produce a valid signature_share (keygen using single dealer).
 * Signature shares are aggregated; the aggregated signature is then verified.
 */
void test_secp256k1_frost_sign_aggregate_verify_to_be_valid(void) {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[3];
    secp256k1_frost_pubkey public_keys[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    threshold_signers = 2;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);

    result = secp256k1_frost_keygen_with_dealer(sign_verify_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_pubkey_from_keypair(&public_keys[index], &keypairs[index]);
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < threshold_signers; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, threshold_signers,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    for (index = 0; index < threshold_signers; index++) {
        unsigned char signature[64];
        /* Step 4: aggregate signature shares */
        result = secp256k1_frost_aggregate(sign_verify_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           threshold_signers);
        CHECK(result == 1);

        /* Step 5: verify aggregated signature */
        result = secp256k1_frost_verify(sign_verify_ctx,
                                        signature,
                                        msg32,
                                        &keypairs[index].public_keys);
        CHECK(result == 1);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
}

/*
 * Try to produce a valid signature_share (keygen using single dealer).
 * Signature shares are aggregated; the aggregated signature is then verified.
 */
void test_secp256k1_frost_sign_aggregate_verify_more_parts_to_be_valid(void) {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[10];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[10];
    secp256k1_frost_pubkey public_keys[10];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[10];
    secp256k1_frost_nonce *nonces[10];
    secp256k1_frost_nonce_commitment signing_commitments[10];

    /* Step 1. initialization */
    num_participants = 10;
    threshold_signers = 8;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(threshold_signers);

    result = secp256k1_frost_keygen_with_dealer(sign_verify_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        result = secp256k1_frost_pubkey_from_keypair(&public_keys[index], &keypairs[index]);
        CHECK(result == 1);
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < threshold_signers; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < threshold_signers; index++) {
        result = secp256k1_frost_sign(&(signature_shares[index]),
                                      msg32, threshold_signers,
                                      &keypairs[index],
                                      nonces[index],
                                      signing_commitments);
        CHECK(result == 1);
    }

    for (index = 0; index < threshold_signers; index++) {
        unsigned char signature[64];
        /* Step 4: aggregate signature shares */
        result = secp256k1_frost_aggregate(sign_verify_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           threshold_signers);
        CHECK(result == 1);

        /* Step 5: verify aggregated signature */
        result = secp256k1_frost_verify(sign_verify_ctx,
                                        signature,
                                        msg32,
                                        &keypairs[index].public_keys);
        CHECK(result == 1);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
}

/*
 * Do not sign when an already used nonce is provided.
 */
void test_secp256k1_frost_sign_with_used_nonce_to_not_sign(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    threshold_signers = 2;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(threshold_signers);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 2: prepare signature commitments */
    for (index = 0; index < threshold_signers; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));

        /* Step 2.b: mark nonce as used */
        nonces[index]->used = 1;
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < threshold_signers; index++) {
        result = secp256k1_frost_sign(&(signature_shares[index]),
                                      msg32, threshold_signers,
                                      &keypairs[index],
                                      nonces[index],
                                      signing_commitments);
        CHECK(result == 0);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to produce a valid signature_share.
 * A larger number of participants and a higher threshold are considered.
 */
void test_secp256k1_frost_with_larger_params_to_be_valid(void) {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[10];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[10];
    secp256k1_frost_pubkey public_keys[10];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[10];
    secp256k1_frost_nonce *nonces[10];
    secp256k1_frost_nonce_commitment signing_commitments[10];

    /* Step 1. initialization */
    num_participants = 10;
    threshold_signers = 6;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(threshold_signers);

    result = secp256k1_frost_keygen_with_dealer(sign_verify_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        memcpy(&public_keys[index], &keypairs[index].public_keys, sizeof(secp256k1_frost_pubkey));
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < threshold_signers; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, threshold_signers,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    for (index = 0; index < threshold_signers; index++) {
        unsigned char signature[64];
        /* Step 4: aggregate signature shares */
        result = secp256k1_frost_aggregate(sign_verify_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           threshold_signers);
        CHECK(result == 1);

        /* Step 5: verify aggregated signature */
        result = secp256k1_frost_verify(sign_verify_ctx,
                                        signature,
                                        msg32,
                                        &keypairs[index].public_keys);
        CHECK(result == 1);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
}

/*
 * Evaluate aggregate (and verify) when all signers provide a signature share.
 * Expected to return 1 (i.e., to be valid).
 */
void test_secp256k1_frost_aggregate_with_all_signers_to_be_valid(void) {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[3];
    secp256k1_frost_pubkey public_keys[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    threshold_signers = 2;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(threshold_signers);

    result = secp256k1_frost_keygen_with_dealer(sign_verify_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        memcpy(&public_keys[index], &keypairs[index].public_keys, sizeof(secp256k1_frost_pubkey));
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < num_participants; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, num_participants,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    for (index = 0; index < num_participants; index++) {
        unsigned char signature[64];
        /* Step 4: aggregate signature shares */
        result = secp256k1_frost_aggregate(sign_verify_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           num_participants);
        CHECK(result == 1);

        /* Step 5: verify aggregated signature */
        result = secp256k1_frost_verify(sign_verify_ctx,
                                        signature,
                                        msg32,
                                        &keypairs[index].public_keys);
        CHECK(result == 1);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
}

void test_secp256k1_frost_aggregate_null_secp_context(void) {
    secp256k1_context *sign_ctx = NULL;
    unsigned char signature[64];
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    secp256k1_frost_keypair keypair;
    secp256k1_frost_pubkey public_keys[3];
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];
    int result;
    const uint32_t num_participants = 3;
    uint32_t index;
    for (index = 0; index < num_participants; index++) {
        memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
        memset(&signature_shares[index], 0, sizeof(secp256k1_frost_signature_share));
        memset(&public_keys[index], 0, sizeof(secp256k1_frost_pubkey));
        memset(&signing_commitments[index], 0, sizeof(secp256k1_frost_nonce_commitment));
    }
    result = secp256k1_frost_aggregate(sign_ctx,
                                       signature,
                                       msg32, &keypair,
                                       public_keys, signing_commitments,
                                       signature_shares,
                                       num_participants);
    CHECK(result == 0);
}

void test_secp256k1_frost_aggregate_null_signature(void) {
    secp256k1_context *sign_ctx;
    unsigned char *signature = NULL;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    secp256k1_frost_keypair keypair;
    secp256k1_frost_pubkey public_keys[3];
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];
    int result;
    const uint32_t num_participants = 3;
    uint32_t index;
    for (index = 0; index < num_participants; index++) {
        memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
        memset(&signature_shares[index], 0, sizeof(secp256k1_frost_signature_share));
        memset(&public_keys[index], 0, sizeof(secp256k1_frost_pubkey));
        memset(&signing_commitments[index], 0, sizeof(secp256k1_frost_nonce_commitment));
    }

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    result = secp256k1_frost_aggregate(sign_ctx,
                                       signature,
                                       msg32, &keypair,
                                       public_keys, signing_commitments,
                                       signature_shares,
                                       num_participants);
    CHECK(result == 0);

    /* Cleaning up */
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_aggregate_null_message(void) {
    secp256k1_context *sign_ctx;
    unsigned char signature[64];
    const unsigned char *msg32 = NULL;
    secp256k1_frost_keypair keypair;
    secp256k1_frost_pubkey public_keys[3];
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];
    int result;
    const uint32_t num_participants = 3;
    uint32_t index;
    for (index = 0; index < num_participants; index++) {
        memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
        memset(&signature_shares[index], 0, sizeof(secp256k1_frost_signature_share));
        memset(&public_keys[index], 0, sizeof(secp256k1_frost_pubkey));
        memset(&signing_commitments[index], 0, sizeof(secp256k1_frost_nonce_commitment));
    }

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    result = secp256k1_frost_aggregate(sign_ctx,
                                       signature,
                                       msg32, &keypair,
                                       public_keys, signing_commitments,
                                       signature_shares,
                                       num_participants);
    CHECK(result == 0);

    /* Cleaning up */
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_aggregate_null_keypair(void) {
    secp256k1_context *sign_ctx;
    unsigned char signature[64];
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    secp256k1_frost_keypair *keypair = NULL;
    secp256k1_frost_pubkey public_keys[3];
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];
    int result;
    const uint32_t num_participants = 3;
    uint32_t index;
    for (index = 0; index < num_participants; index++) {
        memset(&signature_shares[index], 0, sizeof(secp256k1_frost_signature_share));
        memset(&public_keys[index], 0, sizeof(secp256k1_frost_pubkey));
        memset(&signing_commitments[index], 0, sizeof(secp256k1_frost_nonce_commitment));
    }

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    result = secp256k1_frost_aggregate(sign_ctx,
                                       signature,
                                       msg32, keypair,
                                       public_keys, signing_commitments,
                                       signature_shares,
                                       num_participants);
    CHECK(result == 0);

    /* Cleaning up */
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_aggregate_null_pubkeys(void) {
    secp256k1_context *sign_ctx;
    unsigned char signature[64];
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    secp256k1_frost_keypair keypair;
    secp256k1_frost_pubkey *public_keys = NULL;
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];
    int result;
    const uint32_t num_participants = 3;
    uint32_t index;
    for (index = 0; index < num_participants; index++) {
        memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
        memset(&signature_shares[index], 0, sizeof(secp256k1_frost_signature_share));
        memset(&signing_commitments[index], 0, sizeof(secp256k1_frost_nonce_commitment));
    }

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    result = secp256k1_frost_aggregate(sign_ctx,
                                       signature,
                                       msg32, &keypair,
                                       public_keys, signing_commitments,
                                       signature_shares,
                                       num_participants);
    CHECK(result == 0);

    /* Cleaning up */
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_aggregate_null_signing_commitments(void) {
    secp256k1_context *sign_ctx;
    unsigned char signature[64];
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    secp256k1_frost_keypair keypair;
    secp256k1_frost_pubkey public_keys[3];
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce_commitment *signing_commitments = NULL;
    int result;
    const uint32_t num_participants = 3;
    uint32_t index;
    for (index = 0; index < num_participants; index++) {
        memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
        memset(&signature_shares[index], 0, sizeof(secp256k1_frost_signature_share));
        memset(&public_keys[index], 0, sizeof(secp256k1_frost_pubkey));
    }

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    result = secp256k1_frost_aggregate(sign_ctx,
                                       signature,
                                       msg32, &keypair,
                                       public_keys, signing_commitments,
                                       signature_shares,
                                       num_participants);
    CHECK(result == 0);

    /* Cleaning up */
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_aggregate_null_signature_shares(void) {
    secp256k1_context *sign_ctx;
    unsigned char signature[64];
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    secp256k1_frost_keypair keypair;
    secp256k1_frost_pubkey public_keys[3];
    secp256k1_frost_signature_share *signature_shares = NULL;
    secp256k1_frost_nonce_commitment signing_commitments[3];
    int result;
    const uint32_t num_participants = 3;
    uint32_t index;
    for (index = 0; index < num_participants; index++) {
        memset(&keypair, 0, sizeof(secp256k1_frost_keypair));
        memset(&public_keys[index], 0, sizeof(secp256k1_frost_pubkey));
        memset(&signing_commitments[index], 0, sizeof(secp256k1_frost_nonce_commitment));
    }

    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    result = secp256k1_frost_aggregate(sign_ctx,
                                       signature,
                                       msg32, &keypair,
                                       public_keys, signing_commitments,
                                       signature_shares,
                                       num_participants);
    CHECK(result == 0);

    /* Cleaning up */
    secp256k1_context_destroy(sign_ctx);
}

void test_secp256k1_frost_aggregate_with_more_participants_than_max_to_be_invalid(void) {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[3];
    secp256k1_frost_pubkey public_keys[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    threshold_signers = 2;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(threshold_signers);

    result = secp256k1_frost_keygen_with_dealer(sign_verify_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        memcpy(&public_keys[index], &keypairs[index].public_keys, sizeof(secp256k1_frost_pubkey));
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < num_participants; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, num_participants,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    for (index = 0; index < num_participants; index++) {
        unsigned char signature[64];
        /* Step 4: aggregate signature shares */
        result = secp256k1_frost_aggregate(sign_verify_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           num_participants + 1);
        CHECK(result == 0);

    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
}

/*
 * Try to aggregate with less signature_shares than the threshold.
 * Expected to return 0 (invalid).
 */
void test_secp256k1_frost_aggregate_with_few_signature_share_to_be_invalid(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[3];
    secp256k1_frost_pubkey public_keys[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    threshold_signers = 2;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(threshold_signers);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        memcpy(&public_keys[index], &keypairs[index].public_keys, sizeof(secp256k1_frost_pubkey));
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < threshold_signers; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, threshold_signers,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    {
        /* Step 4.pre: consider only a single signature_share for aggregation */
        uint32_t num_signature_share_to_consider;
        num_signature_share_to_consider = 1;

        for (index = 0; index < threshold_signers; index++) {
            unsigned char signature[64];
            /* Step 4: aggregate signature shares */
            result = secp256k1_frost_aggregate(sign_ctx,
                                               signature,
                                               msg32, &keypairs[index],
                                               public_keys, signing_commitments,
                                               signature_shares,
                                               num_signature_share_to_consider);
            CHECK(result == 0);
        }
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to aggregate with an invalid signature_share.
 * Expected to return 0 (invalid).
 */
void test_secp256k1_frost_aggregate_with_invalid_signature_share_to_be_invalid(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[3];
    secp256k1_frost_pubkey public_keys[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    threshold_signers = 2;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(threshold_signers);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        memcpy(&public_keys[index], &keypairs[index].public_keys, sizeof(secp256k1_frost_pubkey));
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < threshold_signers; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, threshold_signers,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    /* Step 3.b: invalidate single signature share */
    memcpy(signature_shares[0].response, msg32, 32);

    for (index = 0; index < threshold_signers; index++) {
        unsigned char signature[64];
        /* Step 4: aggregate signature shares */
        result = secp256k1_frost_aggregate(sign_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           threshold_signers);
        CHECK(result == 0);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Try to aggregate valid signature_share when a wrong group key is provided (keygen using single dealer).
 * Expected to return 0 (invalid).
 */
void test_secp256k1_frost_aggregate_with_invalid_group_key_to_be_invalid(void) {
    secp256k1_context *sign_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[3];
    secp256k1_frost_pubkey public_keys[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    threshold_signers = 2;
    sign_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(threshold_signers);

    result = secp256k1_frost_keygen_with_dealer(sign_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        memcpy(&public_keys[index], &keypairs[index].public_keys, sizeof(secp256k1_frost_pubkey));
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < threshold_signers; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, threshold_signers,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    for (index = 0; index < threshold_signers; index++) {
        unsigned char signature[64];
        /* Step 4: aggregate signature shares */
        memset(keypairs[index].public_keys.group_public_key, 0, 64);
        result = secp256k1_frost_aggregate(sign_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           threshold_signers);
        CHECK(result == 0);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_ctx);
}

/*
 * Produce a valid aggregated signature, but validate with wrong group pubkey.
 * Expected to be invalid.
 */
void test_secp256k1_frost_verify_with_invalid_group_key_to_be_invalid(void) {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    int result;
    uint32_t num_participants;
    uint32_t threshold_signers;
    secp256k1_frost_keypair keypairs[3];
    secp256k1_frost_pubkey public_keys[3];

    uint32_t index;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    threshold_signers = 2;
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    dealer_commitments = secp256k1_frost_vss_commitments_create(threshold_signers);

    result = secp256k1_frost_keygen_with_dealer(sign_verify_ctx,
                                                dealer_commitments,
                                                shares_by_participant,
                                                keypairs, num_participants,
                                                threshold_signers);
    CHECK(result == 1);

    /* Step 1.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        memcpy(&public_keys[index], &keypairs[index].public_keys, sizeof(secp256k1_frost_pubkey));
    }

    /* Step 2: prepare signature commitments */
    for (index = 0; index < threshold_signers; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypairs[index],
                                                     binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 3: compute signature shares */
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, threshold_signers,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    for (index = 0; index < threshold_signers; index++) {
        unsigned char signature[64];
        /* Step 4: aggregate signature shares */
        result = secp256k1_frost_aggregate(sign_verify_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           threshold_signers);
        CHECK(result == 1);

        /* Step 5: verify aggregated signature */
        memset(keypairs[index].public_keys.group_public_key, 0, 64);
        result = secp256k1_frost_verify(sign_verify_ctx,
                                        signature,
                                        msg32,
                                        &keypairs[index].public_keys);
        CHECK(result == 0);
    }

    /* Cleaning up */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < threshold_signers; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
}

/*
 * Try to produce an aggregated signature and validate it.
 * Keygen using DKG.
 */
void test_secp256k1_frost_dkg_sign_aggregate_verify_to_be_valid(void) {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    secp256k1_frost_keygen_secret_share shares_per_participant[3][3];
    int i_share_per_participant[3];
    int result;
    uint32_t num_participants;
    secp256k1_frost_keypair keypairs[3];
    secp256k1_frost_pubkey public_keys[3];
    uint32_t index;
    const unsigned char context[4] = "test";
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[3];
    secp256k1_frost_nonce *nonces[3];
    secp256k1_frost_nonce_commitment signing_commitments[3];

    /* Step 1. initialization */
    num_participants = 3;
    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    for (index = 0; index < num_participants; index++) {
        i_share_per_participant[index] = 0;
        dkg_commitment[index] = secp256k1_frost_vss_commitments_create(2);

    }
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* Step 2. keygen begin and validate for each participant */
    for (index = 0; index < num_participants; index++) {
        uint32_t share_index;
        result = secp256k1_frost_keygen_dkg_begin(sign_verify_ctx,
                                                  dkg_commitment[index],
                                                  shares_by_participant,
                /*num_participants*/  3, /* threshold */ 2,
                                                  index + 1, context, 4);
        CHECK(result == 1);

        result = secp256k1_frost_keygen_dkg_commitment_validate(sign_verify_ctx, dkg_commitment[index], context, 4);
        CHECK(result == 1);

        /* Step 3. dispatching shares for single participant */
        for (share_index = 0; share_index < 3; share_index++) {
            uint32_t spi;
            spi = shares_by_participant[share_index].receiver_index - 1;
            shares_per_participant[spi][i_share_per_participant[spi]] =
                    shares_by_participant[share_index];
            i_share_per_participant[spi]++;
        }
    }

    /* Step 4. keygen finalize for each participant */
    for (index = 0; index < num_participants; index++) {
        result = secp256k1_frost_keygen_dkg_finalize(sign_verify_ctx, &keypairs[index], index + 1, 3,
                                                     shares_per_participant[index],
                                                     dkg_commitment);
        CHECK(result == 1);
    }

    /* Step 4.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        memcpy(&public_keys[index], &keypairs[index].public_keys, sizeof(secp256k1_frost_pubkey));
    }

    /* Step 5: prepare signature commitments */
    for (index = 0; index < num_participants; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypairs[index], binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 6: compute signature shares */
    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, num_participants,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    for (index = 0; index < num_participants; index++) {
        unsigned char signature[64];
        result = secp256k1_frost_aggregate(sign_verify_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           num_participants);
        CHECK(result == 1);

        result = secp256k1_frost_verify(sign_verify_ctx,
                                        signature,
                                        msg32,
                                        &keypairs[index].public_keys);
        CHECK(result == 1);
    }

    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_vss_commitments_destroy(dkg_commitment[index]);
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
    free(dkg_commitment);
}

/*
 * Try to produce an aggregated signature and validate it.
 * Keygen using DKG.
 */
void test_secp256k1_frost_dkg_sign_aggregate_verify_more_parts_to_be_valid(void) {
    secp256k1_context *sign_verify_ctx;
    secp256k1_frost_vss_commitments **dkg_commitment;
    secp256k1_frost_keygen_secret_share shares_by_participant[10];
    secp256k1_frost_keygen_secret_share shares_per_participant[10][10];
    int i_share_per_participant[10];
    int result;
    uint32_t num_participants, threshold;
    secp256k1_frost_keypair keypairs[10];
    secp256k1_frost_pubkey public_keys[10];
    uint32_t index;
    const unsigned char context[4] = "test";
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    secp256k1_frost_signature_share signature_shares[10];
    secp256k1_frost_nonce *nonces[10];
    secp256k1_frost_nonce_commitment signing_commitments[10];

    /* Step 1. initialization */
    num_participants = 10;
    threshold = 8;
    dkg_commitment = malloc(num_participants * sizeof(secp256k1_frost_vss_commitments *));
    for (index = 0; index < num_participants; index++) {
        i_share_per_participant[index] = 0;
        dkg_commitment[index] = secp256k1_frost_vss_commitments_create(threshold);

    }
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);

    /* Step 2. keygen begin and validate for each participant */
    for (index = 0; index < num_participants; index++) {
        uint32_t share_index;
        result = secp256k1_frost_keygen_dkg_begin(sign_verify_ctx,
                                                  dkg_commitment[index],
                                                  shares_by_participant,
                                                  num_participants, threshold,
                                                  index + 1, context, 4);
        CHECK(result == 1);

        result = secp256k1_frost_keygen_dkg_commitment_validate(sign_verify_ctx, dkg_commitment[index], context, 4);
        CHECK(result == 1);

        /* Step 3. dispatching shares for single participant */
        for (share_index = 0; share_index < num_participants; share_index++) {
            uint32_t spi;
            spi = shares_by_participant[share_index].receiver_index - 1;
            shares_per_participant[spi][i_share_per_participant[spi]] =
                    shares_by_participant[share_index];
            i_share_per_participant[spi]++;
        }
    }

    /* Step 4. keygen finalize for each participant */
    for (index = 0; index < num_participants; index++) {
        result = secp256k1_frost_keygen_dkg_finalize(sign_verify_ctx, &keypairs[index], index + 1,
                                                     num_participants,
                                                     shares_per_participant[index],
                                                     dkg_commitment);
        CHECK(result == 1);
    }

    /* Step 4.b: extract public_keys */
    for (index = 0; index < num_participants; index++) {
        memcpy(&public_keys[index], &keypairs[index].public_keys, sizeof(secp256k1_frost_pubkey));
    }

    /* Step 5: prepare signature commitments */
    for (index = 0; index < threshold; index++) {
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx,
                                                     &keypairs[index], binding_seed, hiding_seed);
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Step 6: compute signature shares */
    for (index = 0; index < threshold; index++) {
        secp256k1_frost_sign(&(signature_shares[index]),
                             msg32, threshold,
                             &keypairs[index],
                             nonces[index],
                             signing_commitments);
    }

    for (index = 0; index < threshold; index++) {
        unsigned char signature[64];
        result = secp256k1_frost_aggregate(sign_verify_ctx,
                                           signature,
                                           msg32, &keypairs[index],
                                           public_keys, signing_commitments,
                                           signature_shares,
                                           threshold);
        CHECK(result == 1);

        result = secp256k1_frost_verify(sign_verify_ctx,
                                        signature,
                                        msg32,
                                        &keypairs[index].public_keys);
        CHECK(result == 1);
    }

    for (index = 0; index < num_participants; index++) {
        secp256k1_frost_vss_commitments_destroy(dkg_commitment[index]);
    }
    for (index = 0; index < threshold; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);
    free(dkg_commitment);
}

/*
 * Test serialize and deserialize point.
 */
void test_serialize_and_deserialize_point(void) {
    unsigned char serialized64[64];
    secp256k1_gej point, deserialized_point;
    secp256k1_scalar seed;
    secp256k1_context *test_ctx;
    int is_equal;

    /* Initialize signature */
    test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_scalar_set_int(&seed, 42);
    secp256k1_ecmult_gen(&test_ctx->ecmult_gen_ctx, &point, &seed);

    /* Serialize and deserialize */
    serialize_point(&point, serialized64);
    deserialize_point(&deserialized_point, serialized64);

    is_equal = secp256k1_gej_eq(&point, &deserialized_point);
    CHECK(is_equal == 1);

    secp256k1_context_destroy(test_ctx);
}

/*
 * Test serialize and deserialize functions for frost_signature.
 */
void test_serialize_and_deserialize_frost_signature(void) {
    unsigned char serialized64[64];
    secp256k1_frost_signature signature;
    secp256k1_frost_signature deserialized_signature;
    secp256k1_context *test_ctx;
    int is_equal;

    /* Initialize signature */
    test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_scalar_set_int(&(signature.z), 42);
    secp256k1_ecmult_gen(&test_ctx->ecmult_gen_ctx, &(signature.r), &(signature.z));

    /* Serialize and deserialize */
    serialize_frost_signature(serialized64, &signature);
    CHECK(deserialize_frost_signature(&deserialized_signature, serialized64) == 1);

    is_equal = secp256k1_gej_eq(&(signature.r), &(deserialized_signature.r));
    CHECK(is_equal == 1);

    is_equal = secp256k1_scalar_eq(&(signature.z), &(deserialized_signature.z));
    CHECK(is_equal == 1);

    secp256k1_context_destroy(test_ctx);
}

/*
 * Test save and load a secp256k1_frost_pubkey.
 */
void test_secp256k1_frost_pubkey_save_and_load(void) {
    secp256k1_gej ref_pk, ref_gpk, test_pk, test_gpk;
    secp256k1_scalar seed_pk, seed_gpk;
    secp256k1_context *test_ctx;
    secp256k1_frost_pubkey reference_pubkey, loaded_pubkey;
    unsigned char saved_pubkey[33];
    unsigned char saved_group_pubkey[33];

    /* Initialize public keys */
    test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_scalar_set_int(&seed_pk, 42);
    secp256k1_scalar_set_int(&seed_gpk, 57);
    secp256k1_ecmult_gen(&test_ctx->ecmult_gen_ctx, &ref_pk, &seed_pk);
    secp256k1_ecmult_gen(&test_ctx->ecmult_gen_ctx, &ref_gpk, &seed_gpk);

    /* Prepare reference pubkey */
    reference_pubkey.index = 1;
    reference_pubkey.max_participants = 2;
    serialize_point(&ref_pk, reference_pubkey.public_key);
    serialize_point(&ref_gpk, reference_pubkey.group_public_key);

    /* Save pubkey and check if function returns 1 */
    CHECK(secp256k1_frost_pubkey_save(saved_pubkey, saved_group_pubkey,
                                      &reference_pubkey) == 1);

    /* Load pubkey and check if function returns 1 */
    CHECK(secp256k1_frost_pubkey_load(&loaded_pubkey,
                                      reference_pubkey.index, reference_pubkey.max_participants,
                                      saved_pubkey, saved_group_pubkey) == 1);

    /* Check equality on every field of secp256k1_frost_pubkey */
    deserialize_point(&test_pk, loaded_pubkey.public_key);
    deserialize_point(&test_gpk, loaded_pubkey.group_public_key);

    CHECK(loaded_pubkey.index == reference_pubkey.index);
    CHECK(loaded_pubkey.max_participants == reference_pubkey.max_participants);
    CHECK(secp256k1_gej_eq(&test_pk, &ref_pk) == 1);
    CHECK(secp256k1_gej_eq(&test_gpk, &ref_gpk) == 1);

    secp256k1_context_destroy(test_ctx);
}

/*
 * Test verify function on a signature expected to be valid.
 */
void test_secp256k1_frost_verify_to_be_valid(void) {
    secp256k1_scalar private_key, nonce, challenge;
    secp256k1_gej pubkey;
    secp256k1_context *test_ctx;
    int result;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char serialized64[64];
    secp256k1_frost_signature signature;
    secp256k1_frost_keypair keypair;

    test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_scalar_set_int(&private_key, 42);
    secp256k1_ecmult_gen(&test_ctx->ecmult_gen_ctx, &pubkey, &private_key);
    secp256k1_scalar_set_int(&nonce, 5);
    secp256k1_ecmult_gen(&test_ctx->ecmult_gen_ctx, &(signature.r), &nonce);
    compute_challenge(&challenge, msg32, 32, &pubkey, &(signature.r));

    secp256k1_scalar_mul(&(signature.z), &private_key, &challenge);
    secp256k1_scalar_add(&(signature.z), &nonce, &(signature.z));

    serialize_frost_signature(serialized64, &signature);
    serialize_point(&pubkey, keypair.public_keys.group_public_key);

    result = secp256k1_frost_verify(test_ctx,
                                    serialized64,
                                    msg32,
                                    &keypair.public_keys);
    CHECK(result == 1);

    secp256k1_context_destroy(test_ctx);
}

void test_secp256k1_frost_verify_null_secp_context(void) {
    secp256k1_context *test_ctx = NULL;
    int result;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char serialized64[64] = {0};
    secp256k1_frost_pubkey pubkey;

    memset(&pubkey, 0, sizeof(secp256k1_frost_pubkey));
    result = secp256k1_frost_verify(test_ctx,
                                    serialized64,
                                    msg32,
                                    &pubkey);
    CHECK(result == 0);
}

void test_secp256k1_frost_verify_null_signature(void) {
    secp256k1_context *test_ctx;
    int result;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char *serialized64 = NULL;
    secp256k1_frost_pubkey pubkey;

    test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    memset(&pubkey, 0, sizeof(secp256k1_frost_pubkey));
    result = secp256k1_frost_verify(test_ctx,
                                    serialized64,
                                    msg32,
                                    &pubkey);
    CHECK(result == 0);

    secp256k1_context_destroy(test_ctx);
}

void test_secp256k1_frost_verify_null_message(void) {
    secp256k1_context *test_ctx;
    int result;
    const unsigned char *msg32 = NULL;
    unsigned char serialized64[64] = {0};
    secp256k1_frost_pubkey pubkey;

    test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    memset(&pubkey, 0, sizeof(secp256k1_frost_pubkey));
    result = secp256k1_frost_verify(test_ctx,
                                    serialized64,
                                    msg32,
                                    &pubkey);
    CHECK(result == 0);

    secp256k1_context_destroy(test_ctx);
}

void test_secp256k1_frost_verify_null_pubkey(void) {
    secp256k1_context *test_ctx;
    int result;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char serialized64[64] = {0};
    secp256k1_frost_pubkey *pubkey = NULL;

    test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    result = secp256k1_frost_verify(test_ctx,
                                    serialized64,
                                    msg32,
                                    pubkey);
    CHECK(result == 0);

    secp256k1_context_destroy(test_ctx);
}

/*
 * Test verify function on a signature expected to be invalid.
 */
void test_secp256k1_frost_verify_to_be_invalid(void) {
    secp256k1_scalar private_key, nonce, invalid_nonce, challenge;
    secp256k1_gej pubkey;
    secp256k1_context *test_ctx;
    int result;
    const unsigned char msg32[32] = "zsdW0tL5jv9d1SZsIOUiDIIwWX7n6rgg";
    unsigned char serialized64[64];
    secp256k1_frost_signature signature;
    secp256k1_frost_keypair keypair;

    test_ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    secp256k1_scalar_set_int(&private_key, 42);
    secp256k1_ecmult_gen(&test_ctx->ecmult_gen_ctx, &pubkey, &private_key);
    secp256k1_scalar_set_int(&nonce, 5);
    secp256k1_ecmult_gen(&test_ctx->ecmult_gen_ctx, &(signature.r), &nonce);
    compute_challenge(&challenge, msg32, 32, &pubkey, &(signature.r));

    secp256k1_scalar_mul(&(signature.z), &private_key, &challenge);

    secp256k1_scalar_set_int(&invalid_nonce, 100);
    secp256k1_scalar_add(&(signature.z), &invalid_nonce, &(signature.z));

    serialize_frost_signature(serialized64, &signature);
    serialize_point(&pubkey, keypair.public_keys.group_public_key);

    result = secp256k1_frost_verify(test_ctx,
                                    serialized64,
                                    msg32,
                                    &keypair.public_keys);
    CHECK(result == 0);

    secp256k1_context_destroy(test_ctx);
}

void run_frost_tests(void) {

    /* Test auxiliary internal functions */
    test_secp256k1_gej_eq_case_1();
    test_secp256k1_gej_eq_case_2();
    test_secp256k1_gej_eq_case_3();
    test_secp256k1_gej_eq_case_4();
    test_nonce_generate_with_seed();
    test_nonce_generate_with_no_seed();
    test_serialize_and_deserialize_point();
    test_quicksort_on_signing_commitment();
    test_quicksort_on_signing_commitment_with_duplicates();
    test_serialize_and_deserialize_frost_signature();

    /* Test context creation and destroy functions */
    test_secp256k1_frost_vss_commitments_create_and_destroy();
    test_secp256k1_frost_vss_commitments_create_null_when_threshold_lt_1();
    test_secp256k1_frost_nonce_create_and_destroy();
    test_secp256k1_frost_nonce_create_with_different_nonce();
    test_secp256k1_frost_nonce_create_null_context();
    test_secp256k1_frost_nonce_create_null_keypair();
    test_secp256k1_frost_nonce_create_null_binding_seed();
    test_secp256k1_frost_nonce_create_null_hiding_seed();
    test_secp256k1_frost_nonce_destroy_null_nonce();
    test_secp256k1_frost_keypair_create_and_destroy();
    test_secp256k1_frost_keypair_destroy_null_keypair();
    test_secp256k1_frost_pubkey_save_and_load();

    /* Test key generation (DKG and based on a single dealer) */
    test_secp256k1_frost_keygen_begin();
    test_secp256k1_frost_keygen_begin_null_secp_context();
    test_secp256k1_frost_keygen_begin_null_commitment();
    test_secp256k1_frost_keygen_begin_null_shares();
    test_secp256k1_frost_keygen_begin_null_context();
    test_secp256k1_frost_keygen_begin_invalid_participants();
    test_secp256k1_frost_keygen_begin_invalid_threshold();
    test_secp256k1_frost_keygen_begin_threshold_gt_participants();
    test_secp256k1_frost_keygen_validate();
    test_secp256k1_frost_keygen_validate_null_secp_context();
    test_secp256k1_frost_keygen_validate_null_commitment();
    test_secp256k1_frost_keygen_validate_null_context();
    test_secp256k1_frost_keygen_validate_invalid_secret_commitment();
    test_secp256k1_frost_keygen_validate_invalid_context();
    test_secp256k1_frost_keygen_finalize();
    test_secp256k1_frost_keygen_finalize_null_secp_context();
    test_secp256k1_frost_keygen_finalize_null_keypair();
    test_secp256k1_frost_keygen_finalize_null_shares();
    test_secp256k1_frost_keygen_finalize_null_commitments();
    test_secp256k1_frost_keygen_finalize_is_valid();
    test_secp256k1_frost_keygen_finalize_different_participant_index();
    test_secp256k1_frost_keygen_finalize_invalid_commitments();
    test_secp256k1_frost_keygen_with_single_dealer();
    test_secp256k1_frost_keygen_with_single_dealer_null_secp_context();
    test_secp256k1_frost_keygen_with_single_dealer_null_commitments();
    test_secp256k1_frost_keygen_with_single_dealer_null_shares();
    test_secp256k1_frost_keygen_with_single_dealer_null_keypairs();
    test_secp256k1_frost_keygen_with_single_dealer_is_valid();
    test_secp256k1_frost_keygen_with_single_dealer_invalid_participants();
    test_secp256k1_frost_keygen_with_single_dealer_invalid_threshold();
    test_secp256k1_frost_keygen_with_single_dealer_threshold_gt_participants();

    /* Test sign function */
    test_secp256k1_frost_dkg_and_sign();
    test_secp256k1_frost_dkg_sign_aggregate_verify_to_be_valid();
    test_secp256k1_frost_dkg_sign_aggregate_verify_more_parts_to_be_valid();
    test_secp256k1_frost_single_dealer_and_sign();
    test_secp256k1_frost_sign_aggregate_verify_to_be_valid();
    test_secp256k1_frost_sign_null_signing_commitments();
    test_secp256k1_frost_sign_null_msg32();
    test_secp256k1_frost_sign_null_keypairs();
    test_secp256k1_frost_sign_null_nonces();
    test_secp256k1_frost_sign_null_signature_shares();
    test_secp256k1_frost_sign_more_participants_than_max_to_be_invalid();
    test_secp256k1_frost_sign_aggregate_verify_more_parts_to_be_valid();
    test_secp256k1_frost_sign_with_used_nonce_to_not_sign();

    /* Test aggregate function */
    test_secp256k1_frost_aggregate_with_all_signers_to_be_valid();
    test_secp256k1_frost_aggregate_null_secp_context();
    test_secp256k1_frost_aggregate_null_signature();
    test_secp256k1_frost_aggregate_null_message();
    test_secp256k1_frost_aggregate_null_keypair();
    test_secp256k1_frost_aggregate_null_pubkeys();
    test_secp256k1_frost_aggregate_null_signing_commitments();
    test_secp256k1_frost_aggregate_null_signature_shares();
    test_secp256k1_frost_aggregate_with_invalid_group_key_to_be_invalid();
    test_secp256k1_frost_aggregate_with_invalid_signature_share_to_be_invalid();
    test_secp256k1_frost_aggregate_with_few_signature_share_to_be_invalid();
    test_secp256k1_frost_aggregate_with_more_participants_than_max_to_be_invalid();

    /* Test verify function */
    test_secp256k1_frost_verify_to_be_valid();
    test_secp256k1_frost_verify_to_be_invalid();
    test_secp256k1_frost_verify_with_invalid_group_key_to_be_invalid();
    test_secp256k1_frost_verify_null_secp_context();
    test_secp256k1_frost_verify_null_signature();
    test_secp256k1_frost_verify_null_message();
    test_secp256k1_frost_verify_null_pubkey();

    /* Test overall process with different parameters */
    test_secp256k1_frost_with_larger_params_to_be_valid();

}

#endif /* SECP256K1_MODULE_FROST_TESTS_H */
