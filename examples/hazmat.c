/*************************************************************************
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

#include <assert.h>
#include <stdio.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_hazmat.h>

#include "examples_util.h"

int main(void) {
    secp256k1_context* ctx;
    unsigned char randomize[32];
    secp256k1_hazmat_scalar a[3], a_sum;
    secp256k1_hazmat_point A[3], A_sum;
    unsigned char lhs_ser[33], rhs_ser[33];
    int return_val, i;

    /* Create a secp256k1 context
     * Note that in the hazmat module, the context is only needed for multiplication
     * with the generator point (function `secp256k1_hazmat_multiply_with_generator`).
     */
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return 1;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage. See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail.
     */
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    /* Generate keypairs */
    for (i = 0; i < 3; i++) {
        unsigned char scalar_buf[32];
        unsigned char point_ser[33];

        if (!fill_random(scalar_buf, sizeof(scalar_buf))) {
            printf("Failed to generate randomness\n");
            return 1;
        }
        if (!secp256k1_hazmat_scalar_parse(&a[i], scalar_buf) || secp256k1_hazmat_scalar_is_zero(&a[i])) {
            printf("Generated secret key is invalid. This indicates an issue with the random number generator.\n");
            return 1;
        }
        secp256k1_hazmat_multiply_with_generator(ctx, &A[i], &a[i]);

        secp256k1_hazmat_point_serialize(point_ser, &A[i]);
        printf("scalar a_%d: ", i+1); print_hex(scalar_buf, sizeof(scalar_buf));
        printf("point  A_%d: ", i+1); print_hex(point_ser, sizeof(point_ser));

        secure_erase(scalar_buf, sizeof(scalar_buf));
    }

    /* Simple example: verify that (a_1 + a_2 + a_3) * G = A_1 + A_2 + A_3 holds */
    secp256k1_hazmat_scalar_set_zero(&a_sum);
    secp256k1_hazmat_point_set_infinity(&A_sum);
    for (i = 0; i < 3; i++) {
        secp256k1_hazmat_scalar_add(&a_sum, &a_sum, &a[i]);
        secp256k1_hazmat_point_add(&A_sum, &A_sum, &A[i]);
    }

    {
        secp256k1_hazmat_point A_lhs;

        secp256k1_hazmat_multiply_with_generator(ctx, &A_lhs, &a_sum);
        secp256k1_hazmat_point_serialize(lhs_ser, &A_lhs);
        secp256k1_hazmat_point_serialize(rhs_ser, &A_sum);

        printf("\n");
        printf("(a_1 + a_2 + a_3) * G: ");
        print_hex(lhs_ser, sizeof(lhs_ser));
        printf(" A_1 + A_2 + A_3:      ");
        print_hex(rhs_ser, sizeof(rhs_ser));

        /* Verify equality for both the hazmat points and their serialization */
        return_val = secp256k1_hazmat_point_equal(&A_lhs, &A_sum);
        assert(return_val == 1);
        return_val = memcmp(lhs_ser, rhs_ser, sizeof(lhs_ser));
        assert(return_val == 0);
    }

    /* Next example: verify that a_1 * A_2 = A_1 * a_2 (ECDH) */
    {
        secp256k1_hazmat_point lhs, rhs;

        secp256k1_hazmat_multiply_with_point(&lhs, &a[0], &A[1]);
        secp256k1_hazmat_multiply_with_point(&rhs, &a[1], &A[0]);
        secp256k1_hazmat_point_serialize(lhs_ser, &lhs);
        secp256k1_hazmat_point_serialize(rhs_ser, &rhs);

        printf("\n");
        printf(" a_1 * A_2: ");
        print_hex(lhs_ser, sizeof(lhs_ser));
        printf(" A_1 * a_2: ");
        print_hex(rhs_ser, sizeof(rhs_ser));

        return_val = secp256k1_hazmat_point_equal(&lhs, &rhs);
        assert(return_val == 1);
        return_val = memcmp(lhs_ser, rhs_ser, sizeof(lhs_ser));
        assert(return_val == 0);
    }

    /* Yet another example, to demonstrate also scalar multiplication:
     * verify that (a_1 * a_2) * A_3 = a_1 * (a_2 * A_3) */
    {
        secp256k1_hazmat_point lhs, rhs;
        secp256k1_hazmat_scalar tmp_scalar;
        secp256k1_hazmat_point tmp_point;

        secp256k1_hazmat_scalar_mul(&tmp_scalar, &a[0], &a[1]);
        secp256k1_hazmat_multiply_with_point(&lhs, &tmp_scalar, &A[2]);
        secp256k1_hazmat_multiply_with_point(&tmp_point, &a[1], &A[2]);
        secp256k1_hazmat_multiply_with_point(&rhs, &a[0], &tmp_point);
        secp256k1_hazmat_point_serialize(lhs_ser, &lhs);
        secp256k1_hazmat_point_serialize(rhs_ser, &rhs);

        printf("\n");
        printf("(a_1 * a_2) * A_3:  ");
        print_hex(lhs_ser, sizeof(lhs_ser));
        printf(" a_1 * (a_2 * A_3): ");
        print_hex(rhs_ser, sizeof(rhs_ser));

        return_val = secp256k1_hazmat_point_equal(&lhs, &rhs);
        assert(return_val == 1);
        return_val = memcmp(lhs_ser, rhs_ser, sizeof(lhs_ser));
        assert(return_val == 0);
    }

    /* Show negation and neutral elements for scalars and points:
     * a_i - a_i = 0
     * A_i - A_i = point at infinity
     */
    for (i = 0; i < 3; i++) {
        secp256k1_hazmat_scalar a_result, a_negated;
        secp256k1_hazmat_point A_result, A_negated;

        a_negated = a[i];
        secp256k1_hazmat_scalar_negate(&a_negated);
        secp256k1_hazmat_scalar_add(&a_result, &a[i], &a_negated);
        assert(secp256k1_hazmat_scalar_is_zero(&a_result));

        A_negated = A[i];
        secp256k1_hazmat_point_negate(&A_negated);
        secp256k1_hazmat_point_add(&A_result, &A[i], &A_negated);
        assert(secp256k1_hazmat_point_is_infinity(&A_result));
    }

    /* To demonstrate parsing points and scalars, verify that the discrete log
     * of the generator point is the scalar with value 1. */
    {
        secp256k1_hazmat_point generator, generator_calculated;
        secp256k1_hazmat_scalar scalar_one;
        unsigned char generator_ser[33] =
            "\x02\x79\xBE\x66\x7E\xF9\xDC\xBB\xAC\x55\xA0\x62\x95\xCE\x87\x0B\x07"
                "\x02\x9B\xFC\xDB\x2D\xCE\x28\xD9\x59\xF2\x81\x5B\x16\xF8\x17\x98";
        unsigned char scalar_one_ser[32] =
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
            "\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01";
        unsigned char generator_calculated_ser[33];

        return_val = secp256k1_hazmat_point_parse(&generator, generator_ser);
        assert(return_val);
        return_val = secp256k1_hazmat_scalar_parse(&scalar_one, scalar_one_ser);
        assert(return_val);
        secp256k1_hazmat_multiply_with_generator(ctx, &generator_calculated, &scalar_one);
        secp256k1_hazmat_point_serialize(generator_calculated_ser, &generator_calculated);
        return_val = secp256k1_hazmat_point_equal(&generator, &generator_calculated);
        assert(return_val == 1);
        return_val = memcmp(generator_ser, generator_calculated_ser, sizeof(generator_ser));
        assert(return_val == 0);
    }

    /* It's best practice to try to clear secrets from memory after using them.
     * This is done because some bugs can allow an attacker to leak memory, for
     * example through "out of bounds" array access (see Heartbleed), or the OS
     * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
     *
     * Here we are preventing these writes from being optimized out, as any good compiler
     * will remove any writes that aren't used. */
    for (i = 0; i < 3; i++) {
        secure_erase(&a[i], sizeof(a[i]));
    }
    secure_erase(&a_sum, sizeof(a_sum));

    return 0;
}
