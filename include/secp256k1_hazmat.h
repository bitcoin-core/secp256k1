#ifndef SECP256K1_HAZMAT_H
#define SECP256K1_HAZMAT_H

#include "secp256k1.h"

#ifdef __cplusplus
extern "C" {
#endif

#include <stdint.h>

/* This module provides low-level cryptographic primitives of secp256k1.
 * Note that these can be used incorrectly and require an in-depth knowledge
 * of the cryptographic concepts at work, therefore we call this the
 * "hazardous materials" library or "hazmat" for short.
 */

/* Scalar */
typedef union {
    unsigned char data[32];
    uint64_t align8; /* ensure alignment on 8-bytes boundaries */
} secp256k1_hazmat_scalar;

SECP256K1_API int  secp256k1_hazmat_scalar_parse(secp256k1_hazmat_scalar *s, const unsigned char *bin32);
SECP256K1_API void secp256k1_hazmat_scalar_serialize(unsigned char *bin32, const secp256k1_hazmat_scalar *s);
SECP256K1_API void secp256k1_hazmat_scalar_set_zero(secp256k1_hazmat_scalar *s);
SECP256K1_API int  secp256k1_hazmat_scalar_is_zero(const secp256k1_hazmat_scalar *s);
SECP256K1_API void secp256k1_hazmat_scalar_add(secp256k1_hazmat_scalar *sres, const secp256k1_hazmat_scalar *s1, const secp256k1_hazmat_scalar *s2);
SECP256K1_API void secp256k1_hazmat_scalar_mul(secp256k1_hazmat_scalar *sres, const secp256k1_hazmat_scalar *s1, const secp256k1_hazmat_scalar *s2);
SECP256K1_API void secp256k1_hazmat_scalar_negate(secp256k1_hazmat_scalar *s);

/* Point */
typedef union {
    unsigned char data[160];
    uint64_t align8; /* ensure alignment on 8-bytes boundaries */
} secp256k1_hazmat_point;

SECP256K1_API int  secp256k1_hazmat_point_parse(secp256k1_hazmat_point *p, const unsigned char *pubkey33);
SECP256K1_API void secp256k1_hazmat_point_serialize(unsigned char *pubkey33, secp256k1_hazmat_point *p);
SECP256K1_API void secp256k1_hazmat_point_set_infinity(secp256k1_hazmat_point *p);
SECP256K1_API int  secp256k1_hazmat_point_is_infinity(const secp256k1_hazmat_point *p);
SECP256K1_API void secp256k1_hazmat_point_add(secp256k1_hazmat_point *pres, secp256k1_hazmat_point *p1, secp256k1_hazmat_point *p2);
SECP256K1_API void secp256k1_hazmat_point_negate(secp256k1_hazmat_point *p);
SECP256K1_API int  secp256k1_hazmat_point_equal(const secp256k1_hazmat_point *p1, const secp256k1_hazmat_point *p2);

/* Point multiplication */
SECP256K1_API void secp256k1_hazmat_multiply_with_generator(const secp256k1_context *ctx, secp256k1_hazmat_point *pres, const secp256k1_hazmat_scalar *s);
SECP256K1_API void secp256k1_hazmat_multiply_with_point(secp256k1_hazmat_point *pres, const secp256k1_hazmat_scalar *s, secp256k1_hazmat_point *p);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_HAZMAT_H */
