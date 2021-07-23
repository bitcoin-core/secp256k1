/***********************************************************************
 * Copyright (c) 2021 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_FIELD_REPR_IMPL_H
#define SECP256K1_FIELD_REPR_IMPL_H

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#include "util.h"
#include "field.h"
#include "modinv64_impl.h"

#if defined(USE_EXTERNAL_ASM)
/* External assembler implementation */
void secp256k1_fe_mul_55to5(uint64_t *r, const uint64_t *a, const uint64_t * SECP256K1_RESTRICT b);
void secp256k1_fe_mul_45to5(uint64_t *r, const uint64_t *a, const uint64_t * SECP256K1_RESTRICT b);
void secp256k1_fe_mul_44to5(uint64_t *r, const uint64_t *a, const uint64_t * SECP256K1_RESTRICT b);
void secp256k1_fe_sqr_5to5(uint64_t *r, const uint64_t *a);
void secp256k1_fe_sqr_4to5(uint64_t *r, const uint64_t *a);
void secp256k1_fe_sqr_4to4(uint64_t *r, const uint64_t *a);
#endif

#ifdef VERIFY
#define ON_VERIFY(x) x
#else
#define ON_VERIFY(x)
#endif

#ifdef USE_ASM_X86_64

/* Add a*b to [c0,c1]. c0,c1 must all be 0 on input. */
#define mul2(c0,c1,a,b) do {\
    VERIFY_CHECK(c0 == 0); \
    VERIFY_CHECK(c1 == 0); \
    __asm__ ( \
        "mulq %[vb]\n" \
        : [vc0]"=a"(c0), [vc1]"=d"(c1) \
        : [va]"[vc0]"(a), [vb]"rm"(b) \
        : "cc"); \
} while(0)

/* Add a**2 to [c0,c1]. c0,c1 must all be 0 on input. */
#define sqr2(c0,c1,a) do {\
    VERIFY_CHECK(c0 == 0); \
    VERIFY_CHECK(c1 == 0); \
    __asm__ ( \
        "mulq %[va]\n" \
        : [vc0]"=a"(c0), [vc1]"=d"(c1) \
        : [va]"[vc0]"(a) \
        : "cc"); \
} while(0)

/* Add a*b to [c0,c1,c2]. c2 must never overflow. */
#define muladd3(c0,c1,c2,a,b) do {\
    ON_VERIFY(uint64_t old_c2 = c2;) \
    uint64_t ac = (a); \
    __asm__ ( \
        "mulq %[vb]\n" \
        "addq %%rax, %[vc0]\n" \
        "adcq %%rdx, %[vc1]\n" \
        "adcq $0, %[vc2]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1), [vc2]"+r"(c2), [va]"+a"(ac) \
        : [vb]"rm"(b) \
        : "cc", "rdx"); \
    ON_VERIFY(VERIFY_CHECK(c2 >= old_c2);) \
} while(0)

/* Add a**2 to [c0,c1,c2]. c2 must never overflow. */
#define sqradd3(c0,c1,c2,a) do {\
    ON_VERIFY(uint64_t old_c2 = c2;) \
    uint64_t ac = (a); \
    __asm__ ( \
        "mulq %[va]\n" \
        "addq %%rax, %[vc0]\n" \
        "adcq %%rdx, %[vc1]\n" \
        "adcq $0, %[vc2]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1), [vc2]"+r"(c2), [va]"+a"(ac) \
        : \
        : "cc", "rdx"); \
    ON_VERIFY(VERIFY_CHECK(c2 >= old_c2);) \
} while(0)

/* Add 2*a*b to [c0,c1,c2]. c2 must never overflow. */
#define mul2add3(c0,c1,c2,a,b) do {\
    ON_VERIFY(uint64_t old_c2 = c2;) \
    uint64_t ac = (a); \
    __asm__ ( \
        "mulq %[vb]\n" \
        "addq %%rax, %[vc0]\n" \
        "adcq %%rdx, %[vc1]\n" \
        "adcq $0, %[vc2]\n" \
        "addq %%rax, %[vc0]\n" \
        "adcq %%rdx, %[vc1]\n" \
        "adcq $0, %[vc2]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1), [vc2]"+r"(c2), [va]"+a"(ac) \
        : [vb]"rm"(b) \
        : "cc", "rdx"); \
    ON_VERIFY(VERIFY_CHECK(c2 >= old_c2);) \
} while(0)

/* Add a*b to [c0,c1]. c1 must never overflow. */
#define muladd2(c0,c1,a,b) do {\
    ON_VERIFY(uint64_t old_c1 = c1;) \
    uint64_t ac = (a); \
    __asm__ ( \
        "mulq %[vb]\n" \
        "addq %%rax, %[vc0]\n" \
        "adcq %%rdx, %[vc1]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1), [va]"+a"(ac) \
        : [vb]"rm"(b) \
        : "cc", "rdx"); \
    ON_VERIFY(VERIFY_CHECK(c1 >= old_c1);) \
} while(0)

/* Add a**2 to [c0,c1. c1 must never overflow. */
#define sqradd2(c0,c1,a) do {\
    ON_VERIFY(uint64_t old_c1 = c1;) \
    uint64_t ac = (a); \
    __asm__ ( \
        "mulq %[va]\n" \
        "addq %%rax, %[vc0]\n" \
        "adcq %%rdx, %[vc1]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1), [va]"+a"(ac) \
        : \
        : "cc", "rdx"); \
    ON_VERIFY(VERIFY_CHECK(c1 >= old_c1);) \
} while(0)

/* Add [a0,a1,a2,a3,a4] t0 [c0,c1,c2,c3,c4]. C4 cannot overflow. */
#define add5x5(c0,c1,c2,c3,c4,a0,a1,a2,a3,a4) do {\
    ON_VERIFY(uint64_t old_c4 = c4;) \
    __asm__ ( \
        "addq %[va0], %[vc0]\n" \
        "adcq %[va1], %[vc1]\n" \
        "adcq %[va2], %[vc2]\n" \
        "adcq %[va3], %[vc3]\n" \
        "adcq %[va4], %[vc4]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1), [vc2]"+r"(c2), [vc3]"+r"(c3), [vc4]"+r"(c4) \
        : [va0]"rm"(a0), [va1]"rm"(a1), [va2]"rm"(a2), [va3]"rm"(a3), [va4]"rm"(a4) \
        : "cc" ); \
    ON_VERIFY(VERIFY_CHECK(c4 >= old_c4);) \
} while(0)

/* Add a to [c0,c1,c2,c3]. c3 must never overflow. */
#define add4(c0,c1,c2,c3,a) do {\
    ON_VERIFY(uint64_t old_c3 = c3;) \
    __asm__ ( \
        "addq %[va], %[vc0]\n" \
        "adcq $0, %[vc1]\n" \
        "adcq $0, %[vc2]\n" \
        "adcq $0, %[vc3]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1), [vc2]"+r"(c2), [vc3]"+r"(c3) \
        : [va]"rm"(a) \
        : "cc" ); \
    ON_VERIFY(VERIFY_CHECK(c3 >= old_c3);) \
} while(0)

/* Add a to [c0,c1,c2,c3]. c3 may overflow. */
#define add4o(c0,c1,c2,c3,a) do {\
    __asm__ ( \
        "addq %[va], %[vc0]\n" \
        "adcq $0, %[vc1]\n" \
        "adcq $0, %[vc2]\n" \
        "adcq $0, %[vc3]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1), [vc2]"+r"(c2), [vc3]"+r"(c3) \
        : [va]"rm"(a) \
        : "cc" ); \
} while(0)


/* Add a to [c0,c1,c2]. c2 must never overflow. */
#define add3(c0,c1,c2,a) do {\
    ON_VERIFY(uint64_t old_c2 = c2;) \
    __asm__ ( \
        "addq %[va], %[vc0]\n" \
        "adcq $0, %[vc1]\n" \
        "adcq $0, %[vc2]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1), [vc2]"+r"(c2) \
        : [va]"rm"(a) \
        : "cc" ); \
    ON_VERIFY(VERIFY_CHECK(c2 >= old_c2);) \
} while(0)

/* Add a to [c0,c1]. c1 must never overflow. */
#define add2(c0,c1,a) do {\
    ON_VERIFY(uint64_t old_c1 = c1;) \
    __asm__ ( \
        "addq %[va], %[vc0]\n" \
        "adcq $0, %[vc1]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1) \
        : [va]"rm"(a) \
        : "cc" ); \
    ON_VERIFY(VERIFY_CHECK(c1 >= old_c1);) \
} while(0)

/* Subtract a from [c0,c1]. c1 must never underflow. */
#define sub2(c0,c1,a) do {\
    ON_VERIFY(uint64_t old_c1 = c1;) \
    __asm__ ( \
        "subq %[va], %[vc0]\n" \
        "sbbq $0, %[vc1]\n" \
        : [vc0]"+r"(c0), [vc1]"+r"(c1) \
        : [va]"rm"(a) \
        : "cc" ); \
    ON_VERIFY(VERIFY_CHECK(c1 <= old_c1);) \
} while(0)

#else

/* Fallback using uint128_t. */

/* Add a*b to [c0,c1]. c0,c1 must all be 0 on input. */
#define mul2(c0,c1,a,b) do {\
    uint128_t t = (uint128_t)(a) * (b); \
    VERIFY_CHECK(c0 == 0); \
    VERIFY_CHECK(c1 == 0); \
    c0 = t; \
    c1 = t >> 64; \
} while(0)

/* Add a**2 to [c0,c1]. c0,c1 must all be 0 on input. */
#define sqr2(c0,c1,a) do {\
    uint128_t t = (uint128_t)(a) * (a); \
    VERIFY_CHECK(c0 == 0); \
    VERIFY_CHECK(c1 == 0); \
    c0 = t; \
    c1 = t >> 64; \
} while(0)

/* Add a*b to [c0,c1,c2]. c2 must never overflow. */
#define muladd3(c0,c1,c2,a,b) do {\
    uint64_t tl, th; \
    { \
        uint128_t t = (uint128_t)(a) * (b); \
        th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl);          /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* overflow is handled on the next line */ \
    c2 += (c1 < th);          /* never overflows by contract (verified in the next line) */ \
    VERIFY_CHECK((c1 >= th) || (c2 != 0)); \
} while(0)

/* Add a**2 to [c0,c1,c2]. c2 must never overflow. */
#define sqradd3(c0,c1,c2,a) do {\
    uint64_t tl, th; \
    { \
        uint128_t t = (uint128_t)(a) * (a); \
        th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl);          /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* overflow is handled on the next line */ \
    c2 += (c1 < th);          /* never overflows by contract (verified in the next line) */ \
    VERIFY_CHECK((c1 >= th) || (c2 != 0)); \
} while(0)

/* Add 2*a*b to [c0,c1,c2]. c2 must never overflow. */
#define mul2add3(c0,c1,c2,a,b) do {\
    uint64_t tl, th, th2, tl2; \
    { \
        uint128_t t = (uint128_t)(a) * (b); \
        th = t >> 64;               /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    th2 = th + th;                  /* at most 0xFFFFFFFFFFFFFFFE (in case th was 0x7FFFFFFFFFFFFFFF) */ \
    c2 += (th2 < th);               /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((th2 >= th) || (c2 != 0)); \
    tl2 = tl + tl;                  /* at most 0xFFFFFFFFFFFFFFFE (in case the lowest 63 bits of tl were 0x7FFFFFFFFFFFFFFF) */ \
    th2 += (tl2 < tl);              /* at most 0xFFFFFFFFFFFFFFFF */ \
    c0 += tl2;                      /* overflow is handled on the next line */ \
    th2 += (c0 < tl2);              /* second overflow is handled on the next line */ \
    c2 += (c0 < tl2) & (th2 == 0);  /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); \
    c1 += th2;                      /* overflow is handled on the next line */ \
    c2 += (c1 < th2);               /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((c1 >= th2) || (c2 != 0)); \
} while(0)

/* Add a*b to [c0,c1]. c1 must never overflow. */
#define muladd2(c0,c1,a,b) do {\
    uint64_t tl, th; \
    ON_VERIFY(uint64_t old_c1 = c1;) \
    { \
        uint128_t t = (uint128_t)(a) * (b); \
        th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl);          /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* overflow is handled on the next line */ \
    ON_VERIFY(VERIFY_CHECK(c1 >= old_c1);) \
} while(0)

/* Add a**2 to [c0,c1. c1 must never overflow. */
#define sqradd2(c0,c1,a) do {\
    uint64_t tl, th; \
    ON_VERIFY(uint64_t old_c1 = c1;) \
    { \
        uint128_t t = (uint128_t)(a) * (a); \
        th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl);          /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* overflow is handled on the next line */ \
    ON_VERIFY(VERIFY_CHECK(c1 >= old_c1);) \
} while(0)

/* Add [a0,a1,a2,a3,a4] t0 [c0,c1,c2,c3,c4]. C4 cannot overflow. */
#define add5x5(c0,c1,c2,c3,c4,a0,a1,a2,a3,a4) do {\
    uint128_t tmp = (uint128_t)c0 + (a0); \
    c0 = tmp; tmp >>= 64; \
    tmp += c1; tmp += (a1); \
    c1 = tmp; tmp >>= 64; \
    tmp += c2; tmp += (a2); \
    c2 = tmp; tmp >>= 64; \
    tmp += c3; tmp += (a3); \
    c3 = tmp; tmp >>= 64; \
    tmp += c4; tmp += (a4); \
    c4 = tmp; \
    VERIFY_CHECK((tmp >> 64) == 0); \
} while(0)

/* Add a to [c0,c1,c2,c3]. c3 must never overflow. */
#define add4(c0,c1,c2,c3,a) do {\
    uint128_t tmp = (uint128_t)c0 + (a); \
    c0 = tmp; tmp >>= 64; \
    tmp += c1; \
    c1 = tmp; tmp >>= 64; \
    tmp += c2; \
    c2 = tmp; tmp >>= 64; \
    tmp += c3; \
    c3 = tmp; \
    VERIFY_CHECK((tmp >> 64) == 0); \
} while(0)

/* Add a to [c0,c1,c2,c3]. c3 may overflow. */
#define add4o(c0,c1,c2,c3,a) do {\
    uint128_t tmp = (uint128_t)c0 + (a); \
    c0 = tmp; tmp >>= 64; \
    tmp += c1; \
    c1 = tmp; tmp >>= 64; \
    tmp += c2; \
    c2 = tmp; tmp >>= 64; \
    tmp += c3; \
    c3 = tmp; \
} while(0)


/* Add a to [c0,c1,c2]. c2 must never overflow. */
#define add3(c0,c1,c2,a) do {\
    uint128_t tmp = (uint128_t)c0 + (a); \
    c0 = tmp; tmp >>= 64; \
    tmp += c1; \
    c1 = tmp; tmp >>= 64; \
    tmp += c2; \
    c2 = tmp;  \
    VERIFY_CHECK((tmp >> 64) == 0); \
} while(0)

/* Add a to [c0,c1]. c1 must never overflow. */
#define add2(c0,c1,a) do {\
    uint128_t tmp = (uint128_t)c0 + (a); \
    c0 = tmp; tmp >>= 64; \
    tmp += c1; \
    c1 = tmp; \
    VERIFY_CHECK((tmp >> 64) == 0); \
} while(0)

/* Subtract a from [c0,c1]. c1 must never underflow. */
#define sub2(c0,c1,a) do {\
    int128_t tmp = (int128_t)c0 - (a); \
    c0 = tmp; tmp >>= 64; \
    tmp += c1; \
    c1 = tmp; \
    VERIFY_CHECK((tmp >> 64) == 0); \
} while(0)

#endif

#ifdef VERIFY
static void secp256k1_fe_verify(const secp256k1_fe *a) {
    VERIFY_CHECK(a->magnitude >= 0);
    VERIFY_CHECK(a->magnitude <= 2048);
    if (a->normalized) {
        VERIFY_CHECK(a->n[4] == 0);
        if (~(a->n[0] & a->n[1] & a->n[2] & a->n[3]) == 0) {
            VERIFY_CHECK(a->n[0] <= 0xFFFFFFFEFFFFFC2FULL);
        }
        VERIFY_CHECK(a->magnitude <= 1);
    } else {
        VERIFY_CHECK(a->n[4] <= (((uint64_t)a->magnitude) << 34));
    }
}
#endif

static void secp256k1_fe_normalize(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];
    uint64_t c0 = 0, c1 = 0;

    mul2(c0,c1,t4,0x1000003D1ULL);
    t4 = 0;
    add2(c0,c1,t0);
    t0 = c0;
    add4(t1,t2,t3,t4,c1);
    VERIFY_CHECK(t4 == 0 || t4 == 1);

    c0 = (-(t4 | (((~(t1 & t2 & t3)) == 0) & (t0 >= 0xFFFFFFFEFFFFFC2F)))) & 0x1000003D1ULL;
    add4o(t0,t1,t2,t3,c0);
    t4 = 0;

    r->n[0] = t0;
    r->n[1] = t1;
    r->n[2] = t2;
    r->n[3] = t3;
    r->n[4] = t4;

#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_normalize_weak(secp256k1_fe *r) {
    secp256k1_fe_normalize(r);
}

static void secp256k1_fe_normalize_prec(secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];
    uint64_t c0 = 0, c1 = 0;

    mul2(c0,c1,t4,0x1000003D1ULL);
    t4 = 0;
    add2(c0,c1,t0);
    t0 = c0;
    add4(t1,t2,t3,t4,c1);
    VERIFY_CHECK(t4 == 0 || t4 == 1);

    c0 = (-t4) & 0x1000003D1ULL;
    add4o(t0,t1,t2,t3,c0);

    r->n[0] = t0;
    r->n[1] = t1;
    r->n[2] = t2;
    r->n[3] = t3;
    r->n[4] = 0;

#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 1;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_normalize_weak_prec(secp256k1_fe *r) {
    secp256k1_fe_normalize_prec(r);
}

static void secp256k1_fe_normalize_var(secp256k1_fe *r) {
    secp256k1_fe_normalize(r);
}

static int secp256k1_fe_normalizes_to_zero(const secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];
    uint64_t c0 = 0, c1 = 0;

    mul2(c0,c1,t4,0x1000003D1ULL);
    t4 = 0;
    add2(c0,c1,t0);
    t0 = c0;
    add4(t1,t2,t3,t4,c1);
    VERIFY_CHECK(t4 == 0 || t4 == 1);

    return (t4 == 0) & (((t0 | t1 | t2 | t3) == 0) | ((t0 == 0xFFFFFFFEFFFFFC2F) & ((~(t1 & t2 & t3)) == 0)));
}

static int secp256k1_fe_normalizes_to_zero_var(const secp256k1_fe *r) {
    uint64_t t0 = r->n[0], t1 = r->n[1], t2 = r->n[2], t3 = r->n[3], t4 = r->n[4];
    uint64_t c0 = 0, c1 = 0;

    mul2(c0,c1,t4,0x1000003D1ULL);
    t4 = 0;
    add2(c0,c1,t0);
    t0 = c0;
    add4(t1,t2,t3,t4,c1);
    VERIFY_CHECK(t4 == 0 || t4 == 1);

    return (t4 == 0) && (((t0 | t1 | t2 | t3) == 0) || ((t0 == 0xFFFFFFFEFFFFFC2F) && ((~(t1 & t2 & t3)) == 0)));
}

SECP256K1_INLINE static void secp256k1_fe_set_int(secp256k1_fe *r, int a) {
    r->n[0] = a;
    r->n[1] = r->n[2] = r->n[3] = r->n[4] = 0;
#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

SECP256K1_INLINE static int secp256k1_fe_is_zero(const secp256k1_fe *a) {
    const uint64_t *t = a->n;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    return (t[0] | t[1] | t[2] | t[3] | t[4]) == 0;
}

SECP256K1_INLINE static int secp256k1_fe_is_odd(const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    return a->n[0] & 1;
}

SECP256K1_INLINE static void secp256k1_fe_clear(secp256k1_fe *a) {
    int i;
#ifdef VERIFY
    a->magnitude = 0;
    a->normalized = 1;
#endif
    for (i=0; i<5; i++) {
        a->n[i] = 0;
    }
}

static int secp256k1_fe_cmp_var(const secp256k1_fe *a, const secp256k1_fe *b) {
    int i;
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    VERIFY_CHECK(b->normalized);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b);
#endif
    for (i = 3; i >= 0; i--) {
        if (a->n[i] > b->n[i]) {
            return 1;
        }
        if (a->n[i] < b->n[i]) {
            return -1;
        }
    }
    return 0;
}

static int secp256k1_fe_set_b32(secp256k1_fe *r, const unsigned char *a) {
    int ret;
    r->n[0] = (uint64_t)a[31]
            | ((uint64_t)a[30] << 8)
            | ((uint64_t)a[29] << 16)
            | ((uint64_t)a[28] << 24)
            | ((uint64_t)a[27] << 32)
            | ((uint64_t)a[26] << 40)
            | ((uint64_t)a[25] << 48)
            | ((uint64_t)a[24] << 56);
    r->n[1] = (uint64_t)a[23]
            | ((uint64_t)a[22] << 8)
            | ((uint64_t)a[21] << 16)
            | ((uint64_t)a[20] << 24)
            | ((uint64_t)a[19] << 32)
            | ((uint64_t)a[18] << 40)
            | ((uint64_t)a[17] << 48)
            | ((uint64_t)a[16] << 56);
    r->n[2] = (uint64_t)a[15]
            | ((uint64_t)a[14] << 8)
            | ((uint64_t)a[13] << 16)
            | ((uint64_t)a[12] << 24)
            | ((uint64_t)a[11] << 32)
            | ((uint64_t)a[10] << 40)
            | ((uint64_t)a[9] << 48)
            | ((uint64_t)a[8] << 56);
    r->n[3] = (uint64_t)a[7]
            | ((uint64_t)a[6] << 8)
            | ((uint64_t)a[5] << 16)
            | ((uint64_t)a[4] << 24)
            | ((uint64_t)a[3] << 32)
            | ((uint64_t)a[2] << 40)
            | ((uint64_t)a[1] << 48)
            | ((uint64_t)a[0] << 56);
    r->n[4] = 0;

    ret = !(((r->n[3] & r->n[2] & r->n[1]) == 0xFFFFFFFFFFFFFFFFULL) & (r->n[0] >= 0xFFFFFFFEFFFFFC2FULL));
#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 1;
    r->normalized = ret;
    secp256k1_fe_verify(r);
#endif
    return ret;
}

/** Convert a field element to a 32-byte big endian value. Requires the input to be normalized */
static void secp256k1_fe_get_b32(unsigned char *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
    secp256k1_fe_verify(a);
#endif
    r[0] = (a->n[3] >> 56) & 0xFF;
    r[1] = (a->n[3] >> 48) & 0xFF;
    r[2] = (a->n[3] >> 40) & 0xFF;
    r[3] = (a->n[3] >> 32) & 0xFF;
    r[4] = (a->n[3] >> 24) & 0xFF;
    r[5] = (a->n[3] >> 16) & 0xFF;
    r[6] = (a->n[3] >> 8) & 0xFF;
    r[7] = (a->n[3] >> 0) & 0xFF;
    r[8] = (a->n[2] >> 56) & 0xFF;
    r[9] = (a->n[2] >> 48) & 0xFF;
    r[10] = (a->n[2] >> 40) & 0xFF;
    r[11] = (a->n[2] >> 32) & 0xFF;
    r[12] = (a->n[2] >> 24) & 0xFF;
    r[13] = (a->n[2] >> 16) & 0xFF;
    r[14] = (a->n[2] >> 8) & 0xFF;
    r[15] = (a->n[2] >> 0) & 0xFF;
    r[16] = (a->n[1] >> 56) & 0xFF;
    r[17] = (a->n[1] >> 48) & 0xFF;
    r[18] = (a->n[1] >> 40) & 0xFF;
    r[19] = (a->n[1] >> 32) & 0xFF;
    r[20] = (a->n[1] >> 24) & 0xFF;
    r[21] = (a->n[1] >> 16) & 0xFF;
    r[22] = (a->n[1] >> 8) & 0xFF;
    r[23] = (a->n[1] >> 0) & 0xFF;
    r[24] = (a->n[0] >> 56) & 0xFF;
    r[25] = (a->n[0] >> 48) & 0xFF;
    r[26] = (a->n[0] >> 40) & 0xFF;
    r[27] = (a->n[0] >> 32) & 0xFF;
    r[28] = (a->n[0] >> 24) & 0xFF;
    r[29] = (a->n[0] >> 16) & 0xFF;
    r[30] = (a->n[0] >> 8) & 0xFF;
    r[31] = (a->n[0] >> 0) & 0xFF;
}

SECP256K1_INLINE static void secp256k1_fe_negate(secp256k1_fe *r, const secp256k1_fe *a, int m) {
    uint64_t f = ((uint64_t)(m + 1)) << 34;
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0;

#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= m);
    secp256k1_fe_verify(a);
#endif

    mul2(c0,c1,f,0xFFFFFFFEFFFFFC2F);
    sub2(c0,c1,a->n[0]);
    r->n[0] = c0;
    c2 += f;
    sub2(c1,c2,f);
    sub2(c1,c2,a->n[1]);
    r->n[1] = c1;
    c3 += f;
    sub2(c2,c3,f);
    sub2(c2,c3,a->n[2]);
    r->n[2] = c2;
    c4 += f;
    sub2(c3,c4,f);
    sub2(c3,c4,a->n[3]);
    r->n[3] = c3; 
    VERIFY_CHECK(c4 >= a->n[4]);
    r->n[4] = c4 - a->n[4];

#ifdef VERIFY
    r->magnitude = m + 1;
    r->precomputed = 0;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

SECP256K1_INLINE static void secp256k1_fe_mul_int(secp256k1_fe *r, int a) {
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0;
    uint64_t m = a;
    mul2(c0,c1,r->n[0],m);
    r->n[0] = c0;
    muladd2(c1,c2,r->n[1],m);
    r->n[1] = c1;
    muladd2(c2,c3,r->n[2],m);
    r->n[2] = c2;
    muladd2(c3,c4,r->n[3],m);
    r->n[3] = c3;
    r->n[4] = c4 + (r->n[4] * m);
#ifdef VERIFY
    r->magnitude *= a;
    r->precomputed = 0;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

SECP256K1_INLINE static void secp256k1_fe_add(secp256k1_fe *r, const secp256k1_fe *a) {
    uint64_t c0 = r->n[0], c1 = r->n[1], c2 = r->n[2], c3 = r->n[3], c4 = r->n[4];
#ifdef VERIFY
    secp256k1_fe_verify(r);
    secp256k1_fe_verify(a);
#endif
    add5x5(c0,c1,c2,c3,c4,a->n[0],a->n[1],a->n[2],a->n[3],a->n[4]);
    r->n[0] = c0;
    r->n[1] = c1;
    r->n[2] = c2;
    r->n[3] = c3;
    r->n[4] = c4;
#ifdef VERIFY
    r->magnitude += a->magnitude;
    r->precomputed = 0;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_mul(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b) {
#ifndef USE_EXTERNAL_ASM
    uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4];
    uint64_t b0 = b->n[0], b1 = b->n[1], b2 = b->n[2], b3 = b->n[3], b4 = b->n[4];
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0, c7 = 0;
    uint64_t d0 = 0, d1 = 0, d2 = 0, d3 = 0, d4 = 0;
#endif

#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 2047);
    VERIFY_CHECK(b->magnitude <= 2047);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b);
    VERIFY_CHECK(r != b);
    VERIFY_CHECK(a != b);
#endif

#if defined(USE_EXTERNAL_ASM)
    secp256k1_fe_mul_55to5(r->n, a->n, b->n);
#else
    mul2(c0,c1,a4,0x1000003D1ULL);
    a4 = 0;
    add2(c0,c1,a0);
    a0 = c0;
    add4(a1,a2,a3,a4,c1);
    VERIFY_CHECK(a4 == 0 || a4 == 1);
    c0 = (-(a4)) & 0x1000003D1;
    add4(a0,a1,a2,a3,c0);
    a4 = 0;

    /* Bring b to [0,2**256). */
    c0 = 0;
    c1 = 0;
    mul2(c0,c1,b4,0x1000003D1ULL);
    b4 = 0;
    add2(c0,c1,b0);
    b0 = c0;
    add4(b1,b2,b3,b4,c1);
    VERIFY_CHECK(b4 == 0 || b4 == 1);
    c0 = (-(b4)) & 0x1000003D1;
    add4(b0,b1,b2,b3,c0);
    b4 = 0;

    /* Compute 512-bit product. */
    c0 = 0;
    c1 = 0;
    mul2(c0,c1,a0,b0);
    muladd3(c1,c2,c3,a0,b1);
    muladd3(c1,c2,c3,a1,b0);
    muladd3(c2,c3,c4,a0,b2);
    muladd3(c2,c3,c4,a1,b1);
    muladd3(c2,c3,c4,a2,b0);
    muladd3(c3,c4,c5,a0,b3);
    muladd3(c3,c4,c5,a1,b2);
    muladd3(c3,c4,c5,a2,b1);
    muladd3(c3,c4,c5,a3,b0);
    muladd3(c4,c5,c6,a1,b3);
    muladd3(c4,c5,c6,a2,b2);
    muladd3(c4,c5,c6,a3,b1);
    muladd3(c5,c6,c7,a2,b3);
    muladd3(c5,c6,c7,a3,b2);
    muladd2(c6,c7,a3,b3);

    /* Reduce */
    mul2(d0,d1,c4,0x1000003D1);
    add2(d0,d1,c0);
    r->n[0] = d0;
    muladd2(d1,d2,c5,0x1000003D1);
    add3(d1,d2,d3,c1);
    r->n[1] = d1;
    muladd3(d2,d3,d4,c6,0x1000003D1);
    add3(d2,d3,d4,c2);
    r->n[2] = d2;
    muladd2(d3,d4,c7,0x1000003D1);
    add2(d3,d4,c3);
    r->n[3] = d3;
    r->n[4] = d4;
#endif

#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 0;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_mul_prec(secp256k1_fe *r, const secp256k1_fe *a, const secp256k1_fe * SECP256K1_RESTRICT b_prec) {
#ifndef USE_EXTERNAL_ASM
    uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4];
    uint64_t b0 = b_prec->n[0], b1 = b_prec->n[1], b2 = b_prec->n[2], b3 = b_prec->n[3];
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0, c7 = 0;
    uint64_t d0 = 0, d1 = 0, d2 = 0, d3 = 0, d4 = 0;
#endif

#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 2048);
    VERIFY_CHECK(b_prec->precomputed);
    VERIFY_CHECK(b_prec->n[4] == 0);
    secp256k1_fe_verify(a);
    secp256k1_fe_verify(b_prec);
    VERIFY_CHECK(r != b_prec);
    VERIFY_CHECK(a != b_prec);
#endif

#if defined(USE_EXTERNAL_ASM)
    secp256k1_fe_mul_45to5(r->n, b_prec->n, a->n);
#else
    mul2(c0,c1,a4,0x1000003D1ULL);
    a4 = 0;
    add2(c0,c1,a0);
    a0 = c0;
    add4(a1,a2,a3,a4,c1);
    VERIFY_CHECK(a4 == 0 || a4 == 1);
    c0 = (-(a4)) & 0x1000003D1;
    add4(a0,a1,a2,a3,c0);
    a4 = 0;

    /* Compute 512-bit product. */
    c0 = 0;
    c1 = 0;
    mul2(c0,c1,a0,b0);
    muladd3(c1,c2,c3,a0,b1);
    muladd3(c1,c2,c3,a1,b0);
    muladd3(c2,c3,c4,a0,b2);
    muladd3(c2,c3,c4,a1,b1);
    muladd3(c2,c3,c4,a2,b0);
    muladd3(c3,c4,c5,a0,b3);
    muladd3(c3,c4,c5,a1,b2);
    muladd3(c3,c4,c5,a2,b1);
    muladd3(c3,c4,c5,a3,b0);
    muladd3(c4,c5,c6,a1,b3);
    muladd3(c4,c5,c6,a2,b2);
    muladd3(c4,c5,c6,a3,b1);
    muladd3(c5,c6,c7,a2,b3);
    muladd3(c5,c6,c7,a3,b2);
    muladd2(c6,c7,a3,b3);

    /* Reduce */
    mul2(d0,d1,c4,0x1000003D1);
    add2(d0,d1,c0);
    r->n[0] = d0;
    muladd2(d1,d2,c5,0x1000003D1);
    add3(d1,d2,d3,c1);
    r->n[1] = d1;
    muladd3(d2,d3,d4,c6,0x1000003D1);
    add3(d2,d3,d4,c2);
    r->n[2] = d2;
    muladd2(d3,d4,c7,0x1000003D1);
    add2(d3,d4,c3);
    r->n[3] = d3;
    r->n[4] = d4;
#endif

#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 0;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_mul_2prec(secp256k1_fe *r, const secp256k1_fe *a_prec, const secp256k1_fe * SECP256K1_RESTRICT b_prec) {
#ifndef USE_EXTERNAL_ASM
    uint64_t a0 = a_prec->n[0], a1 = a_prec->n[1], a2 = a_prec->n[2], a3 = a_prec->n[3];
    uint64_t b0 = b_prec->n[0], b1 = b_prec->n[1], b2 = b_prec->n[2], b3 = b_prec->n[3];
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0, c7 = 0;
    uint64_t d0 = 0, d1 = 0, d2 = 0, d3 = 0, d4 = 0;
#endif

#ifdef VERIFY
    VERIFY_CHECK(a_prec->precomputed);
    VERIFY_CHECK(a_prec->n[4] == 0);
    VERIFY_CHECK(b_prec->precomputed);
    VERIFY_CHECK(b_prec->n[4] == 0);
    secp256k1_fe_verify(a_prec);
    secp256k1_fe_verify(b_prec);
    VERIFY_CHECK(r != b_prec);
    VERIFY_CHECK(a_prec != b_prec);
#endif

#if defined(USE_EXTERNAL_ASM)
    secp256k1_fe_mul_44to5(r->n, b_prec->n, a_prec->n);
#else
    /* Compute 512-bit product. */
    c0 = 0;
    c1 = 0;
    mul2(c0,c1,a0,b0);
    muladd3(c1,c2,c3,a0,b1);
    muladd3(c1,c2,c3,a1,b0);
    muladd3(c2,c3,c4,a0,b2);
    muladd3(c2,c3,c4,a1,b1);
    muladd3(c2,c3,c4,a2,b0);
    muladd3(c3,c4,c5,a0,b3);
    muladd3(c3,c4,c5,a1,b2);
    muladd3(c3,c4,c5,a2,b1);
    muladd3(c3,c4,c5,a3,b0);
    muladd3(c4,c5,c6,a1,b3);
    muladd3(c4,c5,c6,a2,b2);
    muladd3(c4,c5,c6,a3,b1);
    muladd3(c5,c6,c7,a2,b3);
    muladd3(c5,c6,c7,a3,b2);
    muladd2(c6,c7,a3,b3);

    /* Reduce */
    mul2(d0,d1,c4,0x1000003D1);
    add2(d0,d1,c0);
    r->n[0] = d0;
    muladd2(d1,d2,c5,0x1000003D1);
    add3(d1,d2,d3,c1);
    r->n[1] = d1;
    muladd3(d2,d3,d4,c6,0x1000003D1);
    add3(d2,d3,d4,c2);
    r->n[2] = d2;
    muladd2(d3,d4,c7,0x1000003D1);
    add2(d3,d4,c3);
    r->n[3] = d3;
    r->n[4] = d4;
#endif

#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 0;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_sqr(secp256k1_fe *r, const secp256k1_fe *a) {
#ifndef USE_EXTERNAL_ASM
    uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3], a4 = a->n[4];
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0, c7 = 0;
    uint64_t d0 = 0, d1 = 0, d2 = 0, d3 = 0, d4 = 0;
#endif

#ifdef VERIFY
    VERIFY_CHECK(a->magnitude <= 2048);
    secp256k1_fe_verify(a);
#endif

#if defined(USE_EXTERNAL_ASM)
    secp256k1_fe_sqr_5to5(r->n, a->n);
#else
    /* Bring a to [0,2**256). */
    mul2(c0,c1,a4,0x1000003D1ULL);
    a4 = 0;
    add2(c0,c1,a0);
    a0 = c0;
    add4(a1,a2,a3,a4,c1);
    VERIFY_CHECK(a4 == 0 || a4 == 1);
    c0 = (-(a4)) & 0x1000003D1;
    add4(a0,a1,a2,a3,c0);

    /* Compute 512-bit product. */
    c0 = 0;
    c1 = 0;
    sqr2(c0,c1,a0);
    mul2add3(c1,c2,c3,a0,a1);
    mul2add3(c2,c3,c4,a0,a2);
    sqradd3(c2,c3,c4,a1);
    mul2add3(c3,c4,c5,a0,a3);
    mul2add3(c3,c4,c5,a1,a2);
    mul2add3(c4,c5,c6,a1,a3);
    sqradd3(c4,c5,c6,a2);
    mul2add3(c5,c6,c7,a2,a3);
    sqradd2(c6,c7,a3);

    /* Reduce */
    mul2(d0,d1,c4,0x1000003D1);
    add2(d0,d1,c0);
    r->n[0] = d0;
    muladd2(d1,d2,c5,0x1000003D1);
    add3(d1,d2,d3,c1);
    r->n[1] = d1;
    muladd3(d2,d3,d4,c6,0x1000003D1);
    add3(d2,d3,d4,c2);
    r->n[2] = d2;
    muladd2(d3,d4,c7,0x1000003D1);
    add2(d3,d4,c3);
    r->n[3] = d3;
    r->n[4] = d4;
#endif

#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 0;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_sqr_prec(secp256k1_fe *r, const secp256k1_fe *a_prec) {
#ifndef USE_EXTERNAL_ASM
    uint64_t a0 = a_prec->n[0], a1 = a_prec->n[1], a2 = a_prec->n[2], a3 = a_prec->n[3];
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0, c7 = 0;
    uint64_t d0 = 0, d1 = 0, d2 = 0, d3 = 0, d4 = 0;
#endif

#ifdef VERIFY
    VERIFY_CHECK(a_prec->precomputed);
    VERIFY_CHECK(a_prec->n[4] == 0);
    secp256k1_fe_verify(a_prec);
#endif

#if defined(USE_EXTERNAL_ASM)
    secp256k1_fe_sqr_4to5(r->n, a_prec->n);
#else
    /* Compute 512-bit product. */
    c0 = 0;
    c1 = 0;
    sqr2(c0,c1,a0);
    mul2add3(c1,c2,c3,a0,a1);
    mul2add3(c2,c3,c4,a0,a2);
    sqradd3(c2,c3,c4,a1);
    mul2add3(c3,c4,c5,a0,a3);
    mul2add3(c3,c4,c5,a1,a2);
    mul2add3(c4,c5,c6,a1,a3);
    sqradd3(c4,c5,c6,a2);
    mul2add3(c5,c6,c7,a2,a3);
    sqradd2(c6,c7,a3);

    /* Reduce */
    mul2(d0,d1,c4,0x1000003D1);
    add2(d0,d1,c0);
    r->n[0] = d0;
    muladd2(d1,d2,c5,0x1000003D1);
    add3(d1,d2,d3,c1);
    r->n[1] = d1;
    muladd3(d2,d3,d4,c6,0x1000003D1);
    add3(d2,d3,d4,c2);
    r->n[2] = d2;
    muladd2(d3,d4,c7,0x1000003D1);
    add2(d3,d4,c3);
    r->n[3] = d3;
    r->n[4] = d4;
#endif

#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 0;
    r->normalized = 0;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_sqr_prec_oprec(secp256k1_fe *r_prec, const secp256k1_fe *a_prec) {
#ifndef USE_EXTERNAL_ASM
    uint64_t a0 = a_prec->n[0], a1 = a_prec->n[1], a2 = a_prec->n[2], a3 = a_prec->n[3];
    uint64_t c0 = 0, c1 = 0, c2 = 0, c3 = 0, c4 = 0, c5 = 0, c6 = 0, c7 = 0;
    uint64_t d0 = 0, d1 = 0, d2 = 0, d3 = 0, d4 = 0;
#endif

#ifdef VERIFY
    VERIFY_CHECK(a_prec->precomputed);
    VERIFY_CHECK(a_prec->n[4] == 0);
    secp256k1_fe_verify(a_prec);
#endif

#if defined(USE_EXTERNAL_ASM)
    secp256k1_fe_sqr_4to4(r_prec->n, a_prec->n);
#else
    /* Compute 512-bit product. */
    c0 = 0;
    c1 = 0;
    sqr2(c0,c1,a0);
    mul2add3(c1,c2,c3,a0,a1);
    mul2add3(c2,c3,c4,a0,a2);
    sqradd3(c2,c3,c4,a1);
    mul2add3(c3,c4,c5,a0,a3);
    mul2add3(c3,c4,c5,a1,a2);
    mul2add3(c4,c5,c6,a1,a3);
    sqradd3(c4,c5,c6,a2);
    mul2add3(c5,c6,c7,a2,a3);
    sqradd2(c6,c7,a3);

    /* Reduce */
    mul2(d0,d1,c4,0x1000003D1);
    add2(d0,d1,c0);
    muladd2(d1,d2,c5,0x1000003D1);
    add3(d1,d2,d3,c1);
    muladd3(d2,d3,d4,c6,0x1000003D1);
    add3(d2,d3,d4,c2);
    muladd2(d3,d4,c7,0x1000003D1);
    add2(d3,d4,c3);

    /* Bring r to [0,2**256). */
    c0 = 0;
    c1 = 0;
    mul2(c0,c1,d4,0x1000003D1ULL);
    d4 = 0;
    add2(c0,c1,d0);
    d0 = c0;
    add4(d1,d2,d3,d4,c1);
    VERIFY_CHECK(d4 == 0 || d4 == 1);
    c0 = (-(d4)) & 0x1000003D1;
    add4(d0,d1,d2,d3,c0);
    r_prec->n[0] = d0;
    r_prec->n[1] = d1;
    r_prec->n[2] = d2;
    r_prec->n[3] = d3;
    r_prec->n[4] = 0;
#endif

#ifdef VERIFY
    r_prec->magnitude = 1;
    r_prec->precomputed = 1;
    r_prec->normalized = 0;
    secp256k1_fe_verify(r_prec);
#endif
}

static SECP256K1_INLINE void secp256k1_fe_cmov(secp256k1_fe *r, const secp256k1_fe *a, int flag) {
    uint64_t mask0, mask1;
    VG_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = flag + ~((uint64_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
    r->n[4] = (r->n[4] & mask0) | (a->n[4] & mask1);
#ifdef VERIFY
    if (flag) {
        r->magnitude = a->magnitude;
        r->precomputed = a->precomputed;
        r->normalized = a->normalized;
    }
#endif
}

static SECP256K1_INLINE void secp256k1_fe_storage_cmov(secp256k1_fe_storage *r, const secp256k1_fe_storage *a, int flag) {
    uint64_t mask0, mask1;
    VG_CHECK_VERIFY(r->n, sizeof(r->n));
    mask0 = flag + ~((uint64_t)0);
    mask1 = ~mask0;
    r->n[0] = (r->n[0] & mask0) | (a->n[0] & mask1);
    r->n[1] = (r->n[1] & mask0) | (a->n[1] & mask1);
    r->n[2] = (r->n[2] & mask0) | (a->n[2] & mask1);
    r->n[3] = (r->n[3] & mask0) | (a->n[3] & mask1);
}

static void secp256k1_fe_to_storage(secp256k1_fe_storage *r, const secp256k1_fe *a) {
#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif
    r->n[0] = a->n[0];
    r->n[1] = a->n[1];
    r->n[2] = a->n[2];
    r->n[3] = a->n[3];
}

static SECP256K1_INLINE void secp256k1_fe_from_storage(secp256k1_fe *r, const secp256k1_fe_storage *a) {
    r->n[0] = a->n[0];
    r->n[1] = a->n[1];
    r->n[2] = a->n[2];
    r->n[3] = a->n[3];
    r->n[4] = 0;
#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 1;
    r->normalized = 1;
#endif
}

static void secp256k1_fe_from_signed62(secp256k1_fe *r, const secp256k1_modinv64_signed62 *a) {
    const uint64_t a0 = a->v[0], a1 = a->v[1], a2 = a->v[2], a3 = a->v[3], a4 = a->v[4];

    /* The output from secp256k1_modinv64{_var} should be normalized to range [0,modulus), and
     * have limbs in [0,2^62). The modulus is < 2^256, so the top limb must be below 2^(256-62*4).
     */
    VERIFY_CHECK(a0 >> 62 == 0);
    VERIFY_CHECK(a1 >> 62 == 0);
    VERIFY_CHECK(a2 >> 62 == 0);
    VERIFY_CHECK(a3 >> 62 == 0);
    VERIFY_CHECK(a4 >> 8 == 0);

    r->n[0] = (a0) | (a1 << 62);
    r->n[1] = (a1 >> 2) | (a2 << 60);
    r->n[2] = (a2 >> 4) | (a3 << 58);
    r->n[3] = (a3 >> 6) | (a4 << 56);
    r->n[4] = 0;

#ifdef VERIFY
    r->magnitude = 1;
    r->precomputed = 1;
    r->normalized = 1;
    secp256k1_fe_verify(r);
#endif
}

static void secp256k1_fe_to_signed62(secp256k1_modinv64_signed62 *r, const secp256k1_fe *a) {
    const uint64_t M62 = UINT64_MAX >> 2;
    const uint64_t a0 = a->n[0], a1 = a->n[1], a2 = a->n[2], a3 = a->n[3];

#ifdef VERIFY
    VERIFY_CHECK(a->normalized);
#endif

    r->v[0] = a0 & M62;
    r->v[1] = (a0 >> 62 | a1 << 2) & M62;
    r->v[2] = (a1 >> 60 | a2 << 4) & M62;
    r->v[3] = (a2 >> 58 | a3 << 6) & M62;
    r->v[4] = (a3 >> 56) & M62;
}

static const secp256k1_modinv64_modinfo secp256k1_const_modinfo_fe = {
    {{-0x1000003D1LL, 0, 0, 0, 256}},
    0x27C7F6E22DDACACFLL
};

static void secp256k1_fe_inv(secp256k1_fe *r, const secp256k1_fe *x) {
    secp256k1_fe tmp;
    secp256k1_modinv64_signed62 s;

    tmp = *x;
    secp256k1_fe_normalize(&tmp);
    secp256k1_fe_to_signed62(&s, &tmp);
    secp256k1_modinv64(&s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed62(r, &s);

#ifdef VERIFY
    VERIFY_CHECK(secp256k1_fe_normalizes_to_zero(r) == secp256k1_fe_normalizes_to_zero(&tmp));
#endif
}

static void secp256k1_fe_inv_var(secp256k1_fe *r, const secp256k1_fe *x) {
    secp256k1_fe tmp;
    secp256k1_modinv64_signed62 s;

    tmp = *x;
    secp256k1_fe_normalize_var(&tmp);
    secp256k1_fe_to_signed62(&s, &tmp);
    secp256k1_modinv64_var(&s, &secp256k1_const_modinfo_fe);
    secp256k1_fe_from_signed62(r, &s);

#ifdef VERIFY
    VERIFY_CHECK(secp256k1_fe_normalizes_to_zero(r) == secp256k1_fe_normalizes_to_zero(&tmp));
#endif
}

#endif /* SECP256K1_FIELD_REPR_IMPL_H */
