#ifndef SECP256K1_EXPORT_H
#define SECP256K1_EXPORT_H

#include "secp256k1.h"
#include <stdint.h>


#ifdef __cplusplus
extern "C" {
#endif

/* taken from "util.h" and extracted necessary part */
#if defined(__SIZEOF_INT128__)
/* If a native 128-bit integer type exists, use int128. */
# define SECP256K1_WIDEMUL_INT128 1
#elif defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64))
/* On 64-bit MSVC targets (x86_64 and arm64), use int128_struct
 * (which has special logic to implement using intrinsics on those systems). */
# define SECP256K1_WIDEMUL_INT128 1
#elif SIZE_MAX > 0xffffffff
/* Systems with 64-bit pointers (and thus registers) very likely benefit from
 * using 64-bit based arithmetic (even if we need to fall back to 32x32->64 based
 * multiplication logic). */
# define SECP256K1_WIDEMUL_INT128 1
#else
/* Lastly, fall back to int64 based arithmetic. */
# define SECP256K1_WIDEMUL_INT64 1
#endif

/* expose secp256k1_scalar to outside */

/* taken from "scalar.h" and extracted necessary part */
#if defined(SECP256K1_WIDEMUL_INT128)
#include "../src/scalar_4x64.h"
#elif defined(SECP256K1_WIDEMUL_INT64)
#include "../src/scalar_8x32.h"
#else
#error "Please select wide multiplication implementation"
#endif

/* taken from field.h to expose secp256k1_fe */

#if defined(SECP256K1_WIDEMUL_INT128)
#include "../src/field_5x52.h"
#elif defined(SECP256K1_WIDEMUL_INT64)
#include "../src/field_10x26.h"
#else
#error "Please select wide multiplication implementation"
#endif

/* since secp256k1_gej in group.h not accessible from outside,
   this defines the identical structure with a different name */
typedef struct {
    secp256k1_fe x;
    secp256k1_fe y;
    secp256k1_fe z;
    int infinity;
} secp256k1_gej_alias;

/* since secp256k1_ge_storage in group.h not accessible from outside,
   this defines the identical structure with a different name */
typedef struct {
    secp256k1_fe_storage x;
    secp256k1_fe_storage y;
} secp256k1_ge_storage_alias;

/* Scalar functions */

SECP256K1_API void secp256k1_export_scalar_clear(
    secp256k1_scalar* r
);

SECP256K1_API int secp256k1_export_scalar_is_equal_to(
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
);

SECP256K1_API int secp256k1_export_scalar_is_zero(
   const  secp256k1_scalar* a
);

SECP256K1_API void secp256k1_export_scalar_negate(
    secp256k1_scalar* r,
    const secp256k1_scalar* a
);

SECP256K1_API void secp256k1_export_scalar_invert(
    secp256k1_scalar* r,
    const secp256k1_scalar* a
);

SECP256K1_API void secp256k1_export_scalar_square(
    secp256k1_scalar* r,
    const secp256k1_scalar* a
);

SECP256K1_API void secp256k1_export_scalar_cube(
    secp256k1_scalar* r,
    const secp256k1_scalar* a
);

SECP256K1_API void secp256k1_export_scalar_add(
    secp256k1_scalar* r,
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
);

SECP256K1_API void secp256k1_export_scalar_sub(
    secp256k1_scalar* r,
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
);

SECP256K1_API void secp256k1_export_scalar_mul(
    secp256k1_scalar* r,
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
);

SECP256K1_API void secp256k1_export_scalar_div(
    secp256k1_scalar* r,
    const secp256k1_scalar* a,
    const secp256k1_scalar* b
);

SECP256K1_API void secp256k1_export_scalar_set_uint32(
    secp256k1_scalar* r,
    const uint32_t n
);

/* buf is expected to have size 32. returns buf modulo the group order */
SECP256K1_API void secp256k1_export_scalar_set_bytes(
    secp256k1_scalar* r,
    const uint8_t* buf
);

SECP256K1_API void secp256k1_export_scalar_get_bytes(
    uint8_t (*buf)[32],
    const secp256k1_scalar* a
);

SECP256K1_API uint32_t secp256k1_export_scalar_get_bits(
    uint8_t offset,
    const secp256k1_scalar* a
);

/* Group functions */

SECP256K1_API void secp256k1_export_group_clear(
    secp256k1_gej_alias* r
);

SECP256K1_API void secp256k1_export_group_get_generator(
    secp256k1_gej_alias* r
);

SECP256K1_API void secp256k1_export_group_serialize(
    secp256k1_ge_storage_alias *r,
    const secp256k1_gej_alias *p
);

SECP256K1_API void secp256k1_export_group_deserialize(
    secp256k1_gej_alias *r,
    const secp256k1_ge_storage_alias *a
);

SECP256K1_API void secp256k1_export_group_add(
    secp256k1_gej_alias* r,
    const secp256k1_gej_alias* a,
    const secp256k1_gej_alias* b
);

SECP256K1_API int secp256k1_export_group_is_equal_to(
    const secp256k1_gej_alias* a,
    const secp256k1_gej_alias* b
);

SECP256K1_API int secp256k1_export_group_is_infinity(
    const secp256k1_gej_alias* a
);

SECP256K1_API void secp256k1_export_group_double(
    secp256k1_gej_alias* r,
    const secp256k1_gej_alias* a
);

SECP256K1_API void secp256k1_export_group_subtract(
    secp256k1_gej_alias* r,
    const secp256k1_gej_alias* a,
    const secp256k1_gej_alias* b
);

SECP256K1_API void secp256k1_export_group_ecmult_const(
    secp256k1_gej_alias *r,
    const secp256k1_gej_alias *a,
    const secp256k1_scalar *q
);

SECP256K1_API int secp256k1_export_group_is_valid(
    const secp256k1_gej_alias* a
);

SECP256K1_API void secp256k1_export_group_set_infinity(
    secp256k1_gej_alias* r
);

/* failure if ret != 1 */
SECP256K1_API int secp256k1_export_group_generator_generate(
    secp256k1_gej_alias* r,
    const uint8_t* key,
    const size_t key_len
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_EXPORT_H */
