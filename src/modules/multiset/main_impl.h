/**********************************************************************
 * Copyright (c) 2017 Tomas van der Wansem                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MULTISET_MAIN_
#define _SECP256K1_MODULE_MULTISET_MAIN_


#include "include/secp256k1_multiset.h"

#include "hash.h"
#include "field.h"
#include "group.h"



/* Hashes the data, and converts the hash to a group element,
 * which encodes the multiset
 *
 * We use trial-and-increment which is fast but non-constant time.
 * Though constant time algo's exist we are not concerned with timing attacks
 * as we make no attempt to hide the underlying data
 */
int secp256k1_multiset_create(const secp256k1_context* ctx,
                              secp256k1_multiset *multiset,
                              const unsigned char *input, size_t inputLen)
{
    static const secp256k1_fe fe_1 = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 1);
    static const secp256k1_fe fe_7 = SECP256K1_FE_CONST(0, 0, 0, 0, 0, 0, 0, 7);

    secp256k1_ge result = {0};
    secp256k1_sha256_t hasher;
    secp256k1_fe_storage hash;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);


    /* first hash the input to result's x */
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, input, inputLen);
    secp256k1_sha256_finalize(&hasher, (unsigned char*) &hash);

    secp256k1_fe_from_storage(&result.x, &hash);
    secp256k1_fe_normalize_var(&result.x);


    /* loop through trials, with 50% success per loop */
    for(;;)
    {
        /* trial candidate x^3 + 7 */
        secp256k1_fe square;
        secp256k1_fe candidate;
        secp256k1_fe_mul(&square, &result.x, &result.x);

        secp256k1_fe_mul(&candidate, &square, &result.x);
        secp256k1_fe_add(&candidate, &fe_7);
        secp256k1_fe_normalize_weak(&candidate);

        if (secp256k1_fe_is_quad_var(&candidate))
        {
            /* result's y is sqrt of candidate */
            int res = secp256k1_fe_sqrt(&result.y, &candidate);
            VERIFY_CHECK(res);
            VERIFY_CHECK(secp256k1_ge_is_valid_var(&result));

            secp256k1_ge_to_storage((secp256k1_ge_storage*) multiset, &result);
            return 1;
        }

        /* increment */
        secp256k1_fe_add(&result.x, &fe_1);
        secp256k1_fe_normalize_weak(&result.x);
    }

}

/* Adds input multiset to multiset */
int secp256k1_multiset_add(const secp256k1_context* ctx, secp256k1_multiset *multiset, const secp256k1_multiset *input)
{
    secp256k1_ge ge_multiset, ge_input, ge_result;
    secp256k1_gej gej_multiset, gej_result;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    /* Conversions */
    secp256k1_ge_from_storage(&ge_multiset, (secp256k1_ge_storage *) multiset);
    secp256k1_ge_from_storage(&ge_input, (secp256k1_ge_storage *) input);

    secp256k1_gej_set_ge(&gej_multiset, &ge_multiset);

    /* Actual adding */
    secp256k1_gej_add_ge_var(&gej_result, &gej_multiset, &ge_input, NULL);

    /* Back conversions */
    secp256k1_ge_set_gej(&ge_result, &gej_result);
    VERIFY_CHECK(secp256k1_ge_is_valid_var(&ge_result));
    VERIFY_CHECK(!ge_result.infinity);

    secp256k1_ge_to_storage((secp256k1_ge_storage*) multiset, &ge_result);

    return 1;
}

/* Removes input multiset from multiset */
int secp256k1_multiset_remove(const secp256k1_context* ctx, secp256k1_multiset *multiset, const secp256k1_multiset *input)
{
    secp256k1_ge ge_multiset, ge_input, ge_result, ge_inv;
    secp256k1_gej gej_multiset, gej_result, gej_input, gej_inv;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(multiset != NULL);
    ARG_CHECK(input != NULL);

    /* Conversions */
    secp256k1_ge_from_storage(&ge_multiset, (secp256k1_ge_storage *) multiset);
    secp256k1_ge_from_storage(&ge_input, (secp256k1_ge_storage *) input);

    secp256k1_gej_set_ge(&gej_multiset, &ge_multiset);
    secp256k1_gej_set_ge(&gej_input, &ge_input);

    /* Negate */
    secp256k1_gej_neg(&gej_inv, &gej_input);
    secp256k1_ge_set_gej(&ge_inv, &gej_inv);

    /* Actual adding */
    secp256k1_gej_add_ge_var(&gej_result, &gej_multiset, &ge_inv, NULL);

    /* Back conversions */
    secp256k1_ge_set_gej(&ge_result, &gej_result);
    VERIFY_CHECK(secp256k1_ge_is_valid_var(&ge_result));
    VERIFY_CHECK(!ge_result.infinity);

    secp256k1_ge_to_storage((secp256k1_ge_storage*) multiset, &ge_result);

    return 1;
}

/* Hash the multiset into resultHash */
int secp256k1_multiset_finalize(const secp256k1_context* ctx, unsigned char *resultHash, const secp256k1_multiset *multiset)
{
    secp256k1_sha256_t hasher;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(resultHash != NULL);
    ARG_CHECK(multiset != NULL);

    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, (unsigned char*)multiset, sizeof(secp256k1_multiset));
    secp256k1_sha256_finalize(&hasher, resultHash);

    return 1;
}

/* Inits the multiset with the constant for empty data  */
int secp256k1_multiset_init(const secp256k1_context* ctx, secp256k1_multiset *multiset) {

    /* This is the multiset for empty data */
    static unsigned char empty[64] = {
        '\xe3', '\xb0', '\xc4', '\x42', '\x98', '\xfc', '\x1c', '\x14',
        '\x9a', '\xfb', '\xf4', '\xc8', '\x99', '\x6f', '\xb9', '\x24',
        '\x27', '\xae', '\x41', '\xe4', '\x64', '\x9b', '\x93', '\x4c',
        '\xa4', '\x95', '\x99', '\x1b', '\x78', '\x52', '\xb8', '\x55',
        '\x31', '\x0c', '\x1e', '\x79', '\x90', '\x48', '\xc0', '\x3f',
        '\x2f', '\x96', '\x72', '\x6d', '\xd9', '\x74', '\xbe', '\xbd',
        '\x43', '\xca', '\x52', '\xe0', '\x97', '\xea', '\x73', '\x5d',
        '\x12', '\xda', '\x54', '\x30', '\x71', '\xae', '\xa3', '\x34'};


    VERIFY_CHECK(ctx != NULL);
    VERIFY_CHECK(sizeof(empty)==sizeof(secp256k1_multiset));

    memcpy(multiset, empty, 64);

    return 1;
}

#endif
