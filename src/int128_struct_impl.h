#ifndef SECP256K1_INT128_STRUCT_IMPL_H
#define SECP256K1_INT128_STRUCT_IMPL_H

#include "int128.h"

#if defined(_MSC_VER) && (defined(_M_X64) || defined(_M_ARM64)) /* MSVC */
  #include <intrin.h>
  #define secp256k1_umulh __umulh
  #define secp256k1_mulh __mulh
#else
static SECP256K1_INLINE uint64_t secp256k1_umulh(uint64_t a, uint64_t b) {
   uint64_t t1 = (uint64_t)(uint32_t)a * (uint32_t)b;
   uint64_t t2 = (a >> 32) * (uint32_t)b;
   uint64_t t3 = (uint32_t)a*(b >> 32) + (t1 >> 32) + (uint32_t)t2;
   return (a >> 32)*(b >> 32) + (t2 >> 32) + (t3 >> 32);
}

static SECP256K1_INLINE int64_t secp256k1_mulh(int64_t a, int64_t b) {
   uint64_t t1 = (uint64_t)(uint32_t)a * (uint32_t)b;
   int64_t t2 = (a >> 32) * (uint32_t)b;
   int64_t t3 = (uint32_t)a * (b >> 32);
   uint64_t t4 = (t1 >> 32) + (uint32_t)t2 + (uint32_t)t3;
   return (a >> 32) * (b >> 32) + (t2 >> 32) + (t3 >> 32) + (int64_t)(t4 >> 32);
}
#endif

static SECP256K1_INLINE void secp256k1_u128_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b) {
   r->hi = secp256k1_umulh(a, b);
   r->lo = a * b;
}

static SECP256K1_INLINE void secp256k1_u128_accum_mul(secp256k1_uint128 *r, uint64_t a, uint64_t b) {
   uint64_t lo = a * b;
   r->hi += secp256k1_umulh(a, b) + (~lo < r->lo);
   r->lo += lo;
}

static SECP256K1_INLINE void secp256k1_u128_accum_u64(secp256k1_uint128 *r, uint64_t a) {
   r->hi += (r->lo > ~a);
   r->lo += a;
}

/* Unsigned (logical) right shift.
 * Non-constant time in n.
 */
static SECP256K1_INLINE void secp256k1_u128_rshift(secp256k1_uint128 *r, unsigned int n) {
   VERIFY_CHECK(n < 128);
   if (n >= 64) {
     r->lo = (r->hi) >> (n-64);
     r->hi = 0;
   } else if (n > 0) {
     r->lo = ((1U * r->hi) << (64-n)) | r->lo >> n;
     r->hi >>= n;
   }
}

static SECP256K1_INLINE uint64_t secp256k1_u128_to_u64(const secp256k1_uint128 *a) {
   return a->lo;
}

static SECP256K1_INLINE uint64_t secp256k1_u128_hi_u64(const secp256k1_uint128 *a) {
   return a->hi;
}

static SECP256K1_INLINE void secp256k1_u128_from_u64(secp256k1_uint128 *r, uint64_t a) {
   r->hi = 0;
   r->lo = a;
}

static SECP256K1_INLINE int secp256k1_u128_check_bits(const secp256k1_uint128 *r, unsigned int n) {
   VERIFY_CHECK(n < 128);
   return n >= 64 ? r->hi >> (n - 64) == 0
                  : r->hi == 0 && r->lo >> n == 0;
}

static SECP256K1_INLINE void secp256k1_i128_mul(secp256k1_int128 *r, int64_t a, int64_t b) {
   r->hi = (uint64_t)secp256k1_mulh(a, b);
   r->lo = (uint64_t)a * (uint64_t)b;
}

static SECP256K1_INLINE void secp256k1_i128_accum_mul(secp256k1_int128 *r, int64_t a, int64_t b) {
   uint64_t lo = (uint64_t)a * (uint64_t)b;
   uint64_t hi = (uint64_t)secp256k1_mulh(a, b) + (~lo < r->lo);
   /* Verify no overflow.
    * If r represents a positive value (the sign bit is not set) and the value we are adding is a positive value (the sign bit is not set),
    * then we require that the resulting value also be positive (the sign bit is not set).
    * Note that (X <= Y) means (X implies Y) when X and Y are boolean values (i.e. 0 or 1).
    */
   VERIFY_CHECK((r->hi <= 0x7fffffffffffffffu && hi <= 0x7fffffffffffffffu) <= (r->hi + hi <= 0x7fffffffffffffffu));
   /* Verify no underflow.
    * If r represents a negative value (the sign bit is set) and the value we are adding is a negative value (the sign bit is set),
    * then we require that the resulting value also be negative (the sign bit is set).
    */
   VERIFY_CHECK((r->hi > 0x7fffffffffffffffu && hi > 0x7fffffffffffffffu) <= (r->hi + hi > 0x7fffffffffffffffu));
   r->hi += hi;
   r->lo += lo;
}

static SECP256K1_INLINE void secp256k1_i128_dissip_mul(secp256k1_int128 *r, int64_t a, int64_t b) {
   uint64_t lo = (uint64_t)a * (uint64_t)b;
   uint64_t hi = (uint64_t)secp256k1_mulh(a, b) + (r->lo < lo);
   /* Verify no overflow.
    * If r represents a positive value (the sign bit is not set) and the value we are subtracting is a negative value (the sign bit is set),
    * then we require that the resulting value also be positive (the sign bit is not set).
    */
   VERIFY_CHECK((r->hi <= 0x7fffffffffffffffu && hi > 0x7fffffffffffffffu) <= (r->hi - hi <= 0x7fffffffffffffffu));
   /* Verify no underflow.
    * If r represents a negative value (the sign bit is set) and the value we are subtracting is a positive value (the sign sign bit is not set),
    * then we require that the resulting value also be negative (the sign bit is set).
    */
   VERIFY_CHECK((r->hi > 0x7fffffffffffffffu && hi <= 0x7fffffffffffffffu) <= (r->hi - hi > 0x7fffffffffffffffu));
   r->hi -= hi;
   r->lo -= lo;
}

static SECP256K1_INLINE void secp256k1_i128_det(secp256k1_int128 *r, int64_t a, int64_t b, int64_t c, int64_t d) {
   secp256k1_i128_mul(r, a, d);
   secp256k1_i128_dissip_mul(r, b, c);
}

/* Signed (arithmetic) right shift.
 * Non-constant time in n.
 */
static SECP256K1_INLINE void secp256k1_i128_rshift(secp256k1_int128 *r, unsigned int n) {
   VERIFY_CHECK(n < 128);
   if (n >= 64) {
     r->lo = (uint64_t)((int64_t)(r->hi) >> (n-64));
     r->hi = (uint64_t)((int64_t)(r->hi) >> 63);
   } else if (n > 0) {
     r->lo = ((1U * r->hi) << (64-n)) | r->lo >> n;
     r->hi = (uint64_t)((int64_t)(r->hi) >> n);
   }
}

static SECP256K1_INLINE int64_t secp256k1_i128_to_i64(const secp256k1_int128 *a) {
   return (int64_t)a->lo;
}

static SECP256K1_INLINE void secp256k1_i128_from_i64(secp256k1_int128 *r, int64_t a) {
   r->hi = (uint64_t)(a >> 63);
   r->lo = (uint64_t)a;
}

static SECP256K1_INLINE int secp256k1_i128_eq_var(const secp256k1_int128 *a, const secp256k1_int128 *b) {
   return a->hi == b->hi && a->lo == b->lo;
}

static SECP256K1_INLINE int secp256k1_i128_check_pow2(const secp256k1_int128 *r, unsigned int n) {
   VERIFY_CHECK(n < 127);
   return n >= 64 ? r->hi == (uint64_t)1 << (n - 64) && r->lo == 0
                  : r->hi == 0 && r->lo == (uint64_t)1 << n;
}

#endif
