#ifndef SECP256K1_INT128_H
#define SECP256K1_INT128_H

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "util.h"

#if defined(SECP256K1_INT128_NATIVE)
#include "int128_native.h"
#elif defined(SECP256K1_INT128_STRUCT)
#include "int128_struct.h"
#else
#error "Please select int128 implementation"
#endif

static SECP256K1_INLINE void secp256k1_u128_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b);

static SECP256K1_INLINE void secp256k1_u128_accum_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b);

static SECP256K1_INLINE void secp256k1_u128_accum_u64(secp256k1_uint128 *r, uint64_t a);

/* Unsigned (logical) right shift.
 * Non-constant time in n.
 */
static SECP256K1_INLINE void secp256k1_u128_rshift(secp256k1_uint128 *r, unsigned int n);

static SECP256K1_INLINE uint64_t secp256k1_u128_to_u64(const secp256k1_uint128 *a);

static SECP256K1_INLINE uint64_t secp256k1_u128_hi_u64(const secp256k1_uint128 *a);

static SECP256K1_INLINE void secp256k1_u128_from_u64(secp256k1_uint128 *r, uint64_t a);

/* Tests if r is strictly less than to 2^n.
 * n must be strictly less than 128.
 */
static SECP256K1_INLINE int secp256k1_u128_check_bits(const secp256k1_uint128 *r, unsigned int n);

static SECP256K1_INLINE void secp256k1_i128_mul(secp256k1_int128 *r, int64_t a, int64_t b);

static SECP256K1_INLINE void secp256k1_i128_accum_mul(secp256k1_int128 *r, int64_t a, int64_t b);

static SECP256K1_INLINE void secp256k1_i128_det(secp256k1_int128 *r, int64_t a, int64_t b, int64_t c, int64_t d);

/* Signed (arithmetic) right shift.
 * Non-constant time in b.
 */
static SECP256K1_INLINE void secp256k1_i128_rshift(secp256k1_int128 *r, unsigned int b);

static SECP256K1_INLINE int64_t secp256k1_i128_to_i64(const secp256k1_int128 *a);

static SECP256K1_INLINE void secp256k1_i128_from_i64(secp256k1_int128 *r, int64_t a);

static SECP256K1_INLINE int secp256k1_i128_eq_var(const secp256k1_int128 *a, const secp256k1_int128 *b);

/* Tests if r is equal to 2^n.
 * n must be strictly less than 127.
 */
static SECP256K1_INLINE int secp256k1_i128_check_pow2(const secp256k1_int128 *r, unsigned int n);

#endif
