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
#endif

/* Macro for restrict, when available and not in a VERIFY build. */
#if defined(SECP256K1_BUILD) && defined(VERIFY)
# define SECP256K1_RESTRICT
#else
# if (!defined(__STDC_VERSION__) || (__STDC_VERSION__ < 199901L) )
#  if SECP256K1_GNUC_PREREQ(3,0)
#   define SECP256K1_RESTRICT __restrict__
#  elif (defined(_MSC_VER) && _MSC_VER >= 1400)
#   define SECP256K1_RESTRICT __restrict
#  else
#   define SECP256K1_RESTRICT
#  endif
# else
#  define SECP256K1_RESTRICT restrict
# endif
#endif

/* expose secp256k1_scalar to outside */

/* taken from "scalar.h" and extracted necessary part */
#if defined(SECP256K1_WIDEMUL_INT128)
#include "../src/scalar_4x64.h"
#else
#error "Please select wide multiplication implementation"
#endif

/* taken from field.h to expose secp256k1_fe */

#ifndef SECP256K1_FE_VERIFY_FIELDS
#define SECP256K1_FE_VERIFY_FIELDS
#endif

#if defined(SECP256K1_WIDEMUL_INT128)
#include "../src/field_5x52.h"
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

/* Field functions */

extern int secp256k1_fe_is_zero(const secp256k1_fe *a);

extern void secp256k1_fe_set_int(secp256k1_fe *r, int a);
                
extern void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a);

extern void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b);

extern void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a);

extern void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *a);

/* Scalar functions */

SECP256K1_API void secp256k1_export_scalar_clear(
    secp256k1_scalar* r
);

SECP256K1_API int secp256k1_export_scalar_eq(
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

SECP256K1_API void secp256k1_export_scalar_inverse(
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

SECP256K1_API void secp256k1_export_scalar_set_int(
    secp256k1_scalar* r,
    const uint32_t n
);

/* buf is expected to have size 32. returns buf modulo the group order */
SECP256K1_API void secp256k1_export_scalar_set_b32(
    secp256k1_scalar* r,
    const uint8_t* buf
);

SECP256K1_API void secp256k1_export_scalar_get_b32(
    uint8_t (*buf)[32],
    const secp256k1_scalar* a
);

SECP256K1_API uint32_t secp256k1_export_scalar_get_bits_limb32(
    uint8_t offset,
    const secp256k1_scalar* a
);

/* Group functions */

SECP256K1_API void secp256k1_export_group_clear(
    secp256k1_gej_alias* r
);

SECP256K1_API void secp256k1_export_group_get_base_point(
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

SECP256K1_API int secp256k1_export_group_eq(
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

SECP256K1_API void secp256k1_export_group_ecmult(
    secp256k1_gej_alias *r,
    const secp256k1_gej_alias* a,
    const secp256k1_scalar *q
);

SECP256K1_API int secp256k1_export_group_is_valid(
    const secp256k1_gej_alias* a
);

SECP256K1_API void secp256k1_export_group_set_infinity(
    secp256k1_gej_alias* r
);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_EXPORT_H */
