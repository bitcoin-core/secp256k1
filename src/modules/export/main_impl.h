/* Copyright (c) 2023 The Navcoin developers
 * Distributed under the MIT software license, see the accompanying
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.
 */

#ifndef SECP256K1_MODULE_EXPORT_MAIN_H
#define SECP256K1_MODULE_EXPORT_MAIN_H

#include "../../../include/secp256k1_export.h"
#include "../../../include/secp256k1.h"
#include "./generator.h"

#define ALIAS_GEJ(x) ((secp256k1_gej_alias*) x)
#define UNALIAS_GEJ(x) ((secp256k1_gej*) x)
#define UNALIAS_GE_STORAGE(x) ((secp256k1_ge_storage*) x)

/* Scalar functions */

SECP256K1_API void secp256k1_export_scalar_clear(
    secp256k1_scalar* r
) {
    secp256k1_scalar_clear(r);
}

SECP256K1_API int secp256k1_export_scalar_is_equal_to(
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
) {
    return secp256k1_scalar_eq(a, b) != 0;
}

SECP256K1_API int secp256k1_export_scalar_is_zero(
    const secp256k1_scalar* a
) {
    return secp256k1_scalar_is_zero(a);
}

SECP256K1_API void secp256k1_export_scalar_negate(
    secp256k1_scalar* r,
    const secp256k1_scalar* a
) {
    secp256k1_scalar_negate(r, a);
}

SECP256K1_API void secp256k1_export_scalar_invert(
    secp256k1_scalar* r,
    const secp256k1_scalar* a
) {
    secp256k1_scalar_inverse(r, a);
}

SECP256K1_API void secp256k1_export_scalar_square(
    secp256k1_scalar* r,
    const secp256k1_scalar* a
) {
    secp256k1_scalar_mul(r, a, a);
}

SECP256K1_API void secp256k1_export_scalar_cube(
    secp256k1_scalar* r,
    const secp256k1_scalar* a
) {
    secp256k1_scalar tmp;
    secp256k1_scalar_mul(&tmp, a, a);
    secp256k1_scalar_mul(r, &tmp, a);
}

SECP256K1_API void secp256k1_export_scalar_add(
    secp256k1_scalar* r,
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
) {
    secp256k1_scalar_add(r, a, b);
}

SECP256K1_API void secp256k1_export_scalar_sub(
    secp256k1_scalar* r,
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
) {
    secp256k1_scalar neg_b;
    secp256k1_scalar_negate(&neg_b, b);
    secp256k1_scalar_add(r, a, &neg_b);
}

SECP256K1_API void secp256k1_export_scalar_mul(
    secp256k1_scalar* r,
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
) {
    secp256k1_scalar_mul(r, a, b);
}

SECP256K1_API void secp256k1_export_scalar_div(
    secp256k1_scalar* r,
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
) {
    secp256k1_scalar inv_b;
    secp256k1_scalar_inverse(&inv_b, b);
    secp256k1_scalar_mul(r, a, &inv_b);
}

SECP256K1_API void secp256k1_export_scalar_set_uint32(
    secp256k1_scalar* r,
    const uint32_t n
) {
    secp256k1_scalar_set_int(r, n);
}

SECP256K1_API void secp256k1_export_scalar_set_bytes(
    secp256k1_scalar* r,
    const uint8_t *buf
) {
    secp256k1_scalar_set_b32(r, buf, NULL);
}

SECP256K1_API void secp256k1_export_scalar_get_bytes(
    uint8_t (*buf)[32],
    const secp256k1_scalar* a
) {
    secp256k1_scalar_get_b32((unsigned char *) buf, a);
}

SECP256K1_API uint32_t secp256k1_export_scalar_get_bits(
    uint8_t offset,
    const secp256k1_scalar* a
) {
    return secp256k1_scalar_get_bits(a, offset, 32);
}

/* Group functions */

static void gej_to_ge(secp256k1_ge* r, const secp256k1_gej* a) {
    secp256k1_fe z_inv, z_inv2, z_inv3;

    secp256k1_fe_inv(&z_inv, &a->z);
    secp256k1_fe_sqr(&z_inv2, &z_inv);
    secp256k1_fe_mul(&z_inv3, &z_inv, &z_inv2);

    secp256k1_fe_mul(&r->x, &a->x, &z_inv2);
    secp256k1_fe_mul(&r->y, &a->y, &z_inv3);

    r->infinity = a->infinity;
}

SECP256K1_API void secp256k1_export_group_clear(
    secp256k1_gej_alias* r
) {
    secp256k1_gej_clear(UNALIAS_GEJ(r));
}

SECP256K1_API void secp256k1_export_group_get_generator(
    secp256k1_gej_alias* r
) {
    secp256k1_gej_set_ge(UNALIAS_GEJ(r), &secp256k1_ge_const_g);
}

SECP256K1_API void secp256k1_export_group_serialize(
    secp256k1_ge_storage_alias *r,
    const secp256k1_gej_alias *a
) {
    secp256k1_ge a_ge;
    secp256k1_ge_set_gej(&a_ge, UNALIAS_GEJ(a));
    secp256k1_ge_to_storage(UNALIAS_GE_STORAGE(r), &a_ge);
}

SECP256K1_API void secp256k1_export_group_deserialize(
    secp256k1_gej_alias *r,
    const secp256k1_ge_storage_alias *a
) {
    secp256k1_ge r_ge;
    secp256k1_ge_from_storage(&r_ge, UNALIAS_GE_STORAGE(a));
    secp256k1_gej_set_ge(UNALIAS_GEJ(r), &r_ge);
}

SECP256K1_API void secp256k1_export_group_add(
    secp256k1_gej_alias* r,
    const secp256k1_gej_alias* a,
    const secp256k1_gej_alias* b
) {
    secp256k1_gej_add_var(UNALIAS_GEJ(r), UNALIAS_GEJ(a), UNALIAS_GEJ(b), NULL);
}

SECP256K1_API int secp256k1_export_group_is_equal_to(
    const secp256k1_gej_alias* a,
    const secp256k1_gej_alias* b
) {
    return secp256k1_gej_eq_var(UNALIAS_GEJ(a), UNALIAS_GEJ(b));
}

SECP256K1_API int secp256k1_export_group_is_infinity(
    const secp256k1_gej_alias* a
) {
    /** Check whether a group element is the point at infinity. */
    return secp256k1_gej_is_infinity(UNALIAS_GEJ(a));
}

SECP256K1_API void secp256k1_export_group_double(
    secp256k1_gej_alias* r,
    const secp256k1_gej_alias* a
) {
    secp256k1_gej_double(UNALIAS_GEJ(r), UNALIAS_GEJ(a));
}

SECP256K1_API void secp256k1_export_group_subtract(
    secp256k1_gej_alias* r,
    const secp256k1_gej_alias* a,
    const secp256k1_gej_alias* b
) {
    secp256k1_gej b_neg;
    secp256k1_gej_neg(&b_neg, UNALIAS_GEJ(b));
    secp256k1_gej_add_var(UNALIAS_GEJ(r), UNALIAS_GEJ(a), &b_neg, NULL);
}

/**
 * Multiply: R = q*A (in constant-time)
 * Here `bits` should be set to the maximum bitlength of the _absolute value_ of `q`, plus
 * one because we internally sometimes add 2 to the number during the WNAF conversion.
 * A must not be infinity.
 */
SECP256K1_API void secp256k1_export_group_ecmult_const(
    secp256k1_gej_alias *r,
    const secp256k1_gej_alias *a,
    const secp256k1_scalar *q
) {
    secp256k1_ge a_ge;

    /* return zero if a is zero */
    if (secp256k1_gej_is_infinity(UNALIAS_GEJ(a)) != 0) {
        secp256k1_gej_set_infinity(UNALIAS_GEJ(r));
        return;
    }
    secp256k1_ge_set_gej(&a_ge, UNALIAS_GEJ(a));
    secp256k1_ecmult_const(UNALIAS_GEJ(r), &a_ge, q, 258); /* 256 + 2 bits */
}

SECP256K1_API int secp256k1_export_group_is_valid(
    const secp256k1_gej_alias* a
) {
    secp256k1_ge a_ge;
    gej_to_ge(&a_ge, UNALIAS_GEJ(a));
    return secp256k1_ge_is_valid_var(&a_ge);
}

SECP256K1_API void secp256k1_export_group_set_infinity(
    secp256k1_gej_alias* r
) {
    secp256k1_gej_set_infinity(UNALIAS_GEJ(r));
}

SECP256K1_API int secp256k1_export_group_generator_generate(
    secp256k1_gej_alias* r,
    const uint8_t* key,
    const size_t key_len
) {
    return secp256k1_generator_generate_internal(UNALIAS_GEJ(r), key, key_len);
}

#endif /* SECP256K1_MODULE_EXPORT_MAIN_H */

