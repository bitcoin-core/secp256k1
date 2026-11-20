#ifndef SECP256K1_INT128_NATIVE_IMPL_H
#define SECP256K1_INT128_NATIVE_IMPL_H

#include "int128.h"
#include "util.h"

static SECP256K1_INLINE void secp256k1_u128_load(secp256k1_uint128 *r, uint64_t hi, uint64_t lo) {
    /* Use | instead of the equivalent +. GCC may reassociate a + with adjacent
     * additions, which can break add-with-carry chains, e.g., in the
     * accumulator of the 4x64 scalar multiplication. */
    *r = (((uint128_t)hi) << 64) | lo;
}

static SECP256K1_INLINE void secp256k1_u128_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b) {
   *r = (uint128_t)a * b;
}

static SECP256K1_INLINE void secp256k1_u128_accum_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b) {
   *r += (uint128_t)a * b;
}

static SECP256K1_INLINE void secp256k1_u128_accum_u64(secp256k1_uint128 *r, uint64_t a) {
   *r += a;
}

/* With __builtin_add_overflow, GCC 14 and newer emit efficient add-with-carry
 * (adc) chains when accumulating several values. The fallbacks compute the carry
 * on 64-bit halves, because computing it as a comparison of 128-bit values can
 * result in branches (observed with GCC 13 to 16). */
static SECP256K1_INLINE int secp256k1_u128_accum_mul_carry(secp256k1_uint128 *r, uint64_t a, uint64_t b) {
#if __has_builtin(__builtin_add_overflow)
   return __builtin_add_overflow(*r, (uint128_t)a * b, r);
#else
   uint128_t t = (uint128_t)a * b;
   uint64_t tl = (uint64_t)t, th = (uint64_t)(t >> 64);
   uint64_t lo = (uint64_t)*r + tl;
   uint64_t hi;
   VERIFY_CHECK(th != UINT64_MAX); /* the high half of a 64x64-bit product is at most 2^64 - 2 */
   th += lo < tl; /* cannot overflow (see above) */
   hi = (uint64_t)(*r >> 64) + th;
   *r = (((uint128_t)hi) << 64) | lo;
   return hi < th;
#endif
}

static SECP256K1_INLINE int secp256k1_u128_accum_u64_carry(secp256k1_uint128 *r, uint64_t a) {
#if __has_builtin(__builtin_add_overflow)
   return __builtin_add_overflow(*r, (uint128_t)a, r);
#else
   uint64_t lo = (uint64_t)*r + a;
   uint64_t c = lo < a;
   uint64_t hi = (uint64_t)(*r >> 64) + c;
   *r = (((uint128_t)hi) << 64) | lo;
   return hi < c;
#endif
}

static SECP256K1_INLINE void secp256k1_u128_rshift(secp256k1_uint128 *r, unsigned int n) {
   VERIFY_CHECK(n < 128);
   *r >>= n;
}

static SECP256K1_INLINE uint64_t secp256k1_u128_to_u64(const secp256k1_uint128 *a) {
   return (uint64_t)(*a);
}

static SECP256K1_INLINE uint64_t secp256k1_u128_hi_u64(const secp256k1_uint128 *a) {
   return (uint64_t)(*a >> 64);
}

static SECP256K1_INLINE void secp256k1_u128_from_u64(secp256k1_uint128 *r, uint64_t a) {
   *r = a;
}

static SECP256K1_INLINE int secp256k1_u128_check_bits(const secp256k1_uint128 *r, unsigned int n) {
   VERIFY_CHECK(n < 128);
   return (*r >> n == 0);
}

static SECP256K1_INLINE void secp256k1_i128_load(secp256k1_int128 *r, int64_t hi, uint64_t lo) {
    *r = (((uint128_t)(uint64_t)hi) << 64) + lo;
}

static SECP256K1_INLINE void secp256k1_i128_mul(secp256k1_int128 *r, int64_t a, int64_t b) {
   *r = (int128_t)a * b;
}

static SECP256K1_INLINE void secp256k1_i128_accum_mul(secp256k1_int128 *r, int64_t a, int64_t b) {
   int128_t ab = (int128_t)a * b;
   VERIFY_CHECK(0 <= ab ? *r <= INT128_MAX - ab : INT128_MIN - ab <= *r);
   *r += ab;
}

static SECP256K1_INLINE void secp256k1_i128_det(secp256k1_int128 *r, int64_t a, int64_t b, int64_t c, int64_t d) {
   int128_t ad = (int128_t)a * d;
   int128_t bc = (int128_t)b * c;
   VERIFY_CHECK(0 <= bc ? INT128_MIN + bc <= ad : ad <= INT128_MAX + bc);
   *r = ad - bc;
}

static SECP256K1_INLINE void secp256k1_i128_rshift(secp256k1_int128 *r, unsigned int n) {
   VERIFY_CHECK(n < 128);
   *r >>= n;
}

static SECP256K1_INLINE uint64_t secp256k1_i128_to_u64(const secp256k1_int128 *a) {
   return (uint64_t)*a;
}

static SECP256K1_INLINE int64_t secp256k1_i128_to_i64(const secp256k1_int128 *a) {
   VERIFY_CHECK(INT64_MIN <= *a && *a <= INT64_MAX);
   return *a;
}

static SECP256K1_INLINE void secp256k1_i128_from_i64(secp256k1_int128 *r, int64_t a) {
   *r = a;
}

static SECP256K1_INLINE int secp256k1_i128_eq_var(const secp256k1_int128 *a, const secp256k1_int128 *b) {
   return *a == *b;
}

static SECP256K1_INLINE int secp256k1_i128_check_pow2(const secp256k1_int128 *r, unsigned int n, int sign) {
   VERIFY_CHECK(n < 127);
   VERIFY_CHECK(sign == 1 || sign == -1);
   return (*r == (int128_t)((uint128_t)sign << n));
}

#endif
