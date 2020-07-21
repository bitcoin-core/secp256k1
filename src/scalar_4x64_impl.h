/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_SCALAR_REPR_IMPL_H
#define SECP256K1_SCALAR_REPR_IMPL_H

/* Limbs of the secp256k1 order. */
#define SECP256K1_N_0 ((uint64_t)0xBFD25E8CD0364141ULL)
#define SECP256K1_N_1 ((uint64_t)0xBAAEDCE6AF48A03BULL)
#define SECP256K1_N_2 ((uint64_t)0xFFFFFFFFFFFFFFFEULL)
#define SECP256K1_N_3 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)

/* Limbs of 2^256 minus the secp256k1 order. */
#define SECP256K1_N_C_0 (~SECP256K1_N_0 + 1)
#define SECP256K1_N_C_1 (~SECP256K1_N_1)
#define SECP256K1_N_C_2 (1)

/* Limbs of half the secp256k1 order. */
#define SECP256K1_N_H_0 ((uint64_t)0xDFE92F46681B20A0ULL)
#define SECP256K1_N_H_1 ((uint64_t)0x5D576E7357A4501DULL)
#define SECP256K1_N_H_2 ((uint64_t)0xFFFFFFFFFFFFFFFFULL)
#define SECP256K1_N_H_3 ((uint64_t)0x7FFFFFFFFFFFFFFFULL)

SECP256K1_INLINE static void secp256k1_scalar_clear(secp256k1_scalar *r) {
    r->d[0] = 0;
    r->d[1] = 0;
    r->d[2] = 0;
    r->d[3] = 0;
}

SECP256K1_INLINE static void secp256k1_scalar_set_int(secp256k1_scalar *r, unsigned int v) {
    r->d[0] = v;
    r->d[1] = 0;
    r->d[2] = 0;
    r->d[3] = 0;
}

SECP256K1_INLINE static unsigned int secp256k1_scalar_get_bits(const secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    VERIFY_CHECK((offset + count - 1) >> 6 == offset >> 6);
    return (a->d[offset >> 6] >> (offset & 0x3F)) & ((((uint64_t)1) << count) - 1);
}

SECP256K1_INLINE static unsigned int secp256k1_scalar_get_bits_var(const secp256k1_scalar *a, unsigned int offset, unsigned int count) {
    VERIFY_CHECK(count < 32);
    VERIFY_CHECK(offset + count <= 256);
    if ((offset + count - 1) >> 6 == offset >> 6) {
        return secp256k1_scalar_get_bits(a, offset, count);
    } else {
        VERIFY_CHECK((offset >> 6) + 1 < 4);
        return ((a->d[offset >> 6] >> (offset & 0x3F)) | (a->d[(offset >> 6) + 1] << (64 - (offset & 0x3F)))) & ((((uint64_t)1) << count) - 1);
    }
}

SECP256K1_INLINE static int secp256k1_scalar_check_overflow(const secp256k1_scalar *a) {
    int yes = 0;
    int no = 0;
    no |= (a->d[3] < SECP256K1_N_3); /* No need for a > check. */
    no |= (a->d[2] < SECP256K1_N_2);
    yes |= (a->d[2] > SECP256K1_N_2) & ~no;
    no |= (a->d[1] < SECP256K1_N_1);
    yes |= (a->d[1] > SECP256K1_N_1) & ~no;
    yes |= (a->d[0] >= SECP256K1_N_0) & ~no;
    return yes;
}

SECP256K1_INLINE static int secp256k1_scalar_reduce(secp256k1_scalar *r, unsigned int overflow) {
    uint128_t t;
    VERIFY_CHECK(overflow <= 1);
    t = (uint128_t)r->d[0] + overflow * SECP256K1_N_C_0;
    r->d[0] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)r->d[1] + overflow * SECP256K1_N_C_1;
    r->d[1] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)r->d[2] + overflow * SECP256K1_N_C_2;
    r->d[2] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint64_t)r->d[3];
    r->d[3] = t & 0xFFFFFFFFFFFFFFFFULL;
    return overflow;
}

static int secp256k1_scalar_add(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
    int overflow;
    uint128_t t = (uint128_t)a->d[0] + b->d[0];
    r->d[0] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)a->d[1] + b->d[1];
    r->d[1] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)a->d[2] + b->d[2];
    r->d[2] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)a->d[3] + b->d[3];
    r->d[3] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    overflow = t + secp256k1_scalar_check_overflow(r);
    VERIFY_CHECK(overflow == 0 || overflow == 1);
    secp256k1_scalar_reduce(r, overflow);
    return overflow;
}

static void secp256k1_scalar_cadd_bit(secp256k1_scalar *r, unsigned int bit, int flag) {
    uint128_t t;
    VERIFY_CHECK(bit < 256);
    bit += ((uint32_t) flag - 1) & 0x100;  /* forcing (bit >> 6) > 3 makes this a noop */
    t = (uint128_t)r->d[0] + (((uint64_t)((bit >> 6) == 0)) << (bit & 0x3F));
    r->d[0] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)r->d[1] + (((uint64_t)((bit >> 6) == 1)) << (bit & 0x3F));
    r->d[1] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)r->d[2] + (((uint64_t)((bit >> 6) == 2)) << (bit & 0x3F));
    r->d[2] = t & 0xFFFFFFFFFFFFFFFFULL; t >>= 64;
    t += (uint128_t)r->d[3] + (((uint64_t)((bit >> 6) == 3)) << (bit & 0x3F));
    r->d[3] = t & 0xFFFFFFFFFFFFFFFFULL;
#ifdef VERIFY
    VERIFY_CHECK((t >> 64) == 0);
    VERIFY_CHECK(secp256k1_scalar_check_overflow(r) == 0);
#endif
}

static void secp256k1_scalar_set_b32(secp256k1_scalar *r, const unsigned char *b32, int *overflow) {
    int over;
    r->d[0] = (uint64_t)b32[31] | (uint64_t)b32[30] << 8 | (uint64_t)b32[29] << 16 | (uint64_t)b32[28] << 24 | (uint64_t)b32[27] << 32 | (uint64_t)b32[26] << 40 | (uint64_t)b32[25] << 48 | (uint64_t)b32[24] << 56;
    r->d[1] = (uint64_t)b32[23] | (uint64_t)b32[22] << 8 | (uint64_t)b32[21] << 16 | (uint64_t)b32[20] << 24 | (uint64_t)b32[19] << 32 | (uint64_t)b32[18] << 40 | (uint64_t)b32[17] << 48 | (uint64_t)b32[16] << 56;
    r->d[2] = (uint64_t)b32[15] | (uint64_t)b32[14] << 8 | (uint64_t)b32[13] << 16 | (uint64_t)b32[12] << 24 | (uint64_t)b32[11] << 32 | (uint64_t)b32[10] << 40 | (uint64_t)b32[9] << 48 | (uint64_t)b32[8] << 56;
    r->d[3] = (uint64_t)b32[7] | (uint64_t)b32[6] << 8 | (uint64_t)b32[5] << 16 | (uint64_t)b32[4] << 24 | (uint64_t)b32[3] << 32 | (uint64_t)b32[2] << 40 | (uint64_t)b32[1] << 48 | (uint64_t)b32[0] << 56;
    over = secp256k1_scalar_reduce(r, secp256k1_scalar_check_overflow(r));
    if (overflow) {
        *overflow = over;
    }
}

static void secp256k1_scalar_get_b32(unsigned char *bin, const secp256k1_scalar* a) {
    bin[0] = a->d[3] >> 56; bin[1] = a->d[3] >> 48; bin[2] = a->d[3] >> 40; bin[3] = a->d[3] >> 32; bin[4] = a->d[3] >> 24; bin[5] = a->d[3] >> 16; bin[6] = a->d[3] >> 8; bin[7] = a->d[3];
    bin[8] = a->d[2] >> 56; bin[9] = a->d[2] >> 48; bin[10] = a->d[2] >> 40; bin[11] = a->d[2] >> 32; bin[12] = a->d[2] >> 24; bin[13] = a->d[2] >> 16; bin[14] = a->d[2] >> 8; bin[15] = a->d[2];
    bin[16] = a->d[1] >> 56; bin[17] = a->d[1] >> 48; bin[18] = a->d[1] >> 40; bin[19] = a->d[1] >> 32; bin[20] = a->d[1] >> 24; bin[21] = a->d[1] >> 16; bin[22] = a->d[1] >> 8; bin[23] = a->d[1];
    bin[24] = a->d[0] >> 56; bin[25] = a->d[0] >> 48; bin[26] = a->d[0] >> 40; bin[27] = a->d[0] >> 32; bin[28] = a->d[0] >> 24; bin[29] = a->d[0] >> 16; bin[30] = a->d[0] >> 8; bin[31] = a->d[0];
}

SECP256K1_INLINE static int secp256k1_scalar_is_zero(const secp256k1_scalar *a) {
    return (a->d[0] | a->d[1] | a->d[2] | a->d[3]) == 0;
}

static void secp256k1_scalar_negate(secp256k1_scalar *r, const secp256k1_scalar *a) {
    uint64_t nonzero = 0xFFFFFFFFFFFFFFFFULL * (secp256k1_scalar_is_zero(a) == 0);
    uint128_t t = (uint128_t)(~a->d[0]) + SECP256K1_N_0 + 1;
    r->d[0] = t & nonzero; t >>= 64;
    t += (uint128_t)(~a->d[1]) + SECP256K1_N_1;
    r->d[1] = t & nonzero; t >>= 64;
    t += (uint128_t)(~a->d[2]) + SECP256K1_N_2;
    r->d[2] = t & nonzero; t >>= 64;
    t += (uint128_t)(~a->d[3]) + SECP256K1_N_3;
    r->d[3] = t & nonzero;
}

SECP256K1_INLINE static int secp256k1_scalar_is_one(const secp256k1_scalar *a) {
    return ((a->d[0] ^ 1) | a->d[1] | a->d[2] | a->d[3]) == 0;
}

static int secp256k1_scalar_is_high(const secp256k1_scalar *a) {
    int yes = 0;
    int no = 0;
    no |= (a->d[3] < SECP256K1_N_H_3);
    yes |= (a->d[3] > SECP256K1_N_H_3) & ~no;
    no |= (a->d[2] < SECP256K1_N_H_2) & ~yes; /* No need for a > check. */
    no |= (a->d[1] < SECP256K1_N_H_1) & ~yes;
    yes |= (a->d[1] > SECP256K1_N_H_1) & ~no;
    yes |= (a->d[0] > SECP256K1_N_H_0) & ~no;
    return yes;
}

static int secp256k1_scalar_cond_negate(secp256k1_scalar *r, int flag) {
    /* If we are flag = 0, mask = 00...00 and this is a no-op;
     * if we are flag = 1, mask = 11...11 and this is identical to secp256k1_scalar_negate */
    uint64_t mask = !flag - 1;
    uint64_t nonzero = (secp256k1_scalar_is_zero(r) != 0) - 1;
    uint128_t t = (uint128_t)(r->d[0] ^ mask) + ((SECP256K1_N_0 + 1) & mask);
    r->d[0] = t & nonzero; t >>= 64;
    t += (uint128_t)(r->d[1] ^ mask) + (SECP256K1_N_1 & mask);
    r->d[1] = t & nonzero; t >>= 64;
    t += (uint128_t)(r->d[2] ^ mask) + (SECP256K1_N_2 & mask);
    r->d[2] = t & nonzero; t >>= 64;
    t += (uint128_t)(r->d[3] ^ mask) + (SECP256K1_N_3 & mask);
    r->d[3] = t & nonzero;
    return 2 * (mask == 0) - 1;
}

/* Inspired by the macros in OpenSSL's crypto/bn/asm/x86_64-gcc.c. */

/** Add a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd(a,b) { \
    uint64_t tl, th; \
    { \
        uint128_t t = (uint128_t)a * b; \
        th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl) ? 1 : 0;  /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* overflow is handled on the next line */ \
    c2 += (c1 < th) ? 1 : 0;  /* never overflows by contract (verified in the next line) */ \
    VERIFY_CHECK((c1 >= th) || (c2 != 0)); \
}

/** Add a*b to the number defined by (c0,c1). c1 must never overflow. */
#define muladd_fast(a,b) { \
    uint64_t tl, th; \
    { \
        uint128_t t = (uint128_t)a * b; \
        th = t >> 64;         /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    c0 += tl;                 /* overflow is handled on the next line */ \
    th += (c0 < tl) ? 1 : 0;  /* at most 0xFFFFFFFFFFFFFFFF */ \
    c1 += th;                 /* never overflows by contract (verified in the next line) */ \
    VERIFY_CHECK(c1 >= th); \
}

/** Add 2*a*b to the number defined by (c0,c1,c2). c2 must never overflow. */
#define muladd2(a,b) { \
    uint64_t tl, th, th2, tl2; \
    { \
        uint128_t t = (uint128_t)a * b; \
        th = t >> 64;               /* at most 0xFFFFFFFFFFFFFFFE */ \
        tl = t; \
    } \
    th2 = th + th;                  /* at most 0xFFFFFFFFFFFFFFFE (in case th was 0x7FFFFFFFFFFFFFFF) */ \
    c2 += (th2 < th) ? 1 : 0;       /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((th2 >= th) || (c2 != 0)); \
    tl2 = tl + tl;                  /* at most 0xFFFFFFFFFFFFFFFE (in case the lowest 63 bits of tl were 0x7FFFFFFFFFFFFFFF) */ \
    th2 += (tl2 < tl) ? 1 : 0;      /* at most 0xFFFFFFFFFFFFFFFF */ \
    c0 += tl2;                      /* overflow is handled on the next line */ \
    th2 += (c0 < tl2) ? 1 : 0;      /* second overflow is handled on the next line */ \
    c2 += (c0 < tl2) & (th2 == 0);  /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((c0 >= tl2) || (th2 != 0) || (c2 != 0)); \
    c1 += th2;                      /* overflow is handled on the next line */ \
    c2 += (c1 < th2) ? 1 : 0;       /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((c1 >= th2) || (c2 != 0)); \
}

/** Add a to the number defined by (c0,c1,c2). c2 must never overflow. */
#define sumadd(a) { \
    unsigned int over; \
    c0 += (a);                  /* overflow is handled on the next line */ \
    over = (c0 < (a)) ? 1 : 0; \
    c1 += over;                 /* overflow is handled on the next line */ \
    c2 += (c1 < over) ? 1 : 0;  /* never overflows by contract */ \
}

/** Add a to the number defined by (c0,c1). c1 must never overflow, c2 must be zero. */
#define sumadd_fast(a) { \
    c0 += (a);                 /* overflow is handled on the next line */ \
    c1 += (c0 < (a)) ? 1 : 0;  /* never overflows by contract (verified the next line) */ \
    VERIFY_CHECK((c1 != 0) | (c0 >= (a))); \
    VERIFY_CHECK(c2 == 0); \
}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. */
#define extract(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = c2; \
    c2 = 0; \
}

/** Extract the lowest 64 bits of (c0,c1,c2) into n, and left shift the number 64 bits. c2 is required to be zero. */
#define extract_fast(n) { \
    (n) = c0; \
    c0 = c1; \
    c1 = 0; \
    VERIFY_CHECK(c2 == 0); \
}

static void secp256k1_scalar_reduce_512(secp256k1_scalar *r, const uint64_t *l) {
#ifdef USE_ASM_X86_64
    /* Reduce 512 bits into 385. */
    uint64_t m0, m1, m2, m3, m4, m5, m6;
    uint64_t p0, p1, p2, p3, p4;
    uint64_t c;

    __asm__ __volatile__(
    /* Preload. */
    "movq 32(%%rsi), %%r11\n"
    "movq 40(%%rsi), %%r12\n"
    "movq 48(%%rsi), %%r13\n"
    "movq 56(%%rsi), %%r14\n"
    /* Initialize r8,r9,r10 */
    "movq 0(%%rsi), %%r8\n"
    "xorq %%r9, %%r9\n"
    "xorq %%r10, %%r10\n"
    /* (r8,r9) += n0 * c0 */
    "movq %8, %%rax\n"
    "mulq %%r11\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    /* extract m0 */
    "movq %%r8, %q0\n"
    "xorq %%r8, %%r8\n"
    /* (r9,r10) += l1 */
    "addq 8(%%rsi), %%r9\n"
    "adcq $0, %%r10\n"
    /* (r9,r10,r8) += n1 * c0 */
    "movq %8, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* (r9,r10,r8) += n0 * c1 */
    "movq %9, %%rax\n"
    "mulq %%r11\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* extract m1 */
    "movq %%r9, %q1\n"
    "xorq %%r9, %%r9\n"
    /* (r10,r8,r9) += l2 */
    "addq 16(%%rsi), %%r10\n"
    "adcq $0, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r10,r8,r9) += n2 * c0 */
    "movq %8, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r10,r8,r9) += n1 * c1 */
    "movq %9, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r10,r8,r9) += n0 */
    "addq %%r11, %%r10\n"
    "adcq $0, %%r8\n"
    "adcq $0, %%r9\n"
    /* extract m2 */
    "movq %%r10, %q2\n"
    "xorq %%r10, %%r10\n"
    /* (r8,r9,r10) += l3 */
    "addq 24(%%rsi), %%r8\n"
    "adcq $0, %%r9\n"
    "adcq $0, %%r10\n"
    /* (r8,r9,r10) += n3 * c0 */
    "movq %8, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* (r8,r9,r10) += n2 * c1 */
    "movq %9, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* (r8,r9,r10) += n1 */
    "addq %%r12, %%r8\n"
    "adcq $0, %%r9\n"
    "adcq $0, %%r10\n"
    /* extract m3 */
    "movq %%r8, %q3\n"
    "xorq %%r8, %%r8\n"
    /* (r9,r10,r8) += n3 * c1 */
    "movq %9, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* (r9,r10,r8) += n2 */
    "addq %%r13, %%r9\n"
    "adcq $0, %%r10\n"
    "adcq $0, %%r8\n"
    /* extract m4 */
    "movq %%r9, %q4\n"
    /* (r10,r8) += n3 */
    "addq %%r14, %%r10\n"
    "adcq $0, %%r8\n"
    /* extract m5 */
    "movq %%r10, %q5\n"
    /* extract m6 */
    "movq %%r8, %q6\n"
    : "=g"(m0), "=g"(m1), "=g"(m2), "=g"(m3), "=g"(m4), "=g"(m5), "=g"(m6)
    : "S"(l), "i"(SECP256K1_N_C_0), "i"(SECP256K1_N_C_1)
    : "rax", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "cc");

    /* Reduce 385 bits into 258. */
    __asm__ __volatile__(
    /* Preload */
    "movq %q9, %%r11\n"
    "movq %q10, %%r12\n"
    "movq %q11, %%r13\n"
    /* Initialize (r8,r9,r10) */
    "movq %q5, %%r8\n"
    "xorq %%r9, %%r9\n"
    "xorq %%r10, %%r10\n"
    /* (r8,r9) += m4 * c0 */
    "movq %12, %%rax\n"
    "mulq %%r11\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    /* extract p0 */
    "movq %%r8, %q0\n"
    "xorq %%r8, %%r8\n"
    /* (r9,r10) += m1 */
    "addq %q6, %%r9\n"
    "adcq $0, %%r10\n"
    /* (r9,r10,r8) += m5 * c0 */
    "movq %12, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* (r9,r10,r8) += m4 * c1 */
    "movq %13, %%rax\n"
    "mulq %%r11\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* extract p1 */
    "movq %%r9, %q1\n"
    "xorq %%r9, %%r9\n"
    /* (r10,r8,r9) += m2 */
    "addq %q7, %%r10\n"
    "adcq $0, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r10,r8,r9) += m6 * c0 */
    "movq %12, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r10,r8,r9) += m5 * c1 */
    "movq %13, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r10,r8,r9) += m4 */
    "addq %%r11, %%r10\n"
    "adcq $0, %%r8\n"
    "adcq $0, %%r9\n"
    /* extract p2 */
    "movq %%r10, %q2\n"
    /* (r8,r9) += m3 */
    "addq %q8, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r8,r9) += m6 * c1 */
    "movq %13, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    /* (r8,r9) += m5 */
    "addq %%r12, %%r8\n"
    "adcq $0, %%r9\n"
    /* extract p3 */
    "movq %%r8, %q3\n"
    /* (r9) += m6 */
    "addq %%r13, %%r9\n"
    /* extract p4 */
    "movq %%r9, %q4\n"
    : "=&g"(p0), "=&g"(p1), "=&g"(p2), "=g"(p3), "=g"(p4)
    : "g"(m0), "g"(m1), "g"(m2), "g"(m3), "g"(m4), "g"(m5), "g"(m6), "i"(SECP256K1_N_C_0), "i"(SECP256K1_N_C_1)
    : "rax", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "cc");

    /* Reduce 258 bits into 256. */
    __asm__ __volatile__(
    /* Preload */
    "movq %q5, %%r10\n"
    /* (rax,rdx) = p4 * c0 */
    "movq %7, %%rax\n"
    "mulq %%r10\n"
    /* (rax,rdx) += p0 */
    "addq %q1, %%rax\n"
    "adcq $0, %%rdx\n"
    /* extract r0 */
    "movq %%rax, 0(%q6)\n"
    /* Move to (r8,r9) */
    "movq %%rdx, %%r8\n"
    "xorq %%r9, %%r9\n"
    /* (r8,r9) += p1 */
    "addq %q2, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r8,r9) += p4 * c1 */
    "movq %8, %%rax\n"
    "mulq %%r10\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    /* Extract r1 */
    "movq %%r8, 8(%q6)\n"
    "xorq %%r8, %%r8\n"
    /* (r9,r8) += p4 */
    "addq %%r10, %%r9\n"
    "adcq $0, %%r8\n"
    /* (r9,r8) += p2 */
    "addq %q3, %%r9\n"
    "adcq $0, %%r8\n"
    /* Extract r2 */
    "movq %%r9, 16(%q6)\n"
    "xorq %%r9, %%r9\n"
    /* (r8,r9) += p3 */
    "addq %q4, %%r8\n"
    "adcq $0, %%r9\n"
    /* Extract r3 */
    "movq %%r8, 24(%q6)\n"
    /* Extract c */
    "movq %%r9, %q0\n"
    : "=g"(c)
    : "g"(p0), "g"(p1), "g"(p2), "g"(p3), "g"(p4), "D"(r), "i"(SECP256K1_N_C_0), "i"(SECP256K1_N_C_1)
    : "rax", "rdx", "r8", "r9", "r10", "cc", "memory");
#else
    uint128_t c;
    uint64_t c0, c1, c2;
    uint64_t n0 = l[4], n1 = l[5], n2 = l[6], n3 = l[7];
    uint64_t m0, m1, m2, m3, m4, m5;
    uint32_t m6;
    uint64_t p0, p1, p2, p3;
    uint32_t p4;

    /* Reduce 512 bits into 385. */
    /* m[0..6] = l[0..3] + n[0..3] * SECP256K1_N_C. */
    c0 = l[0]; c1 = 0; c2 = 0;
    muladd_fast(n0, SECP256K1_N_C_0);
    extract_fast(m0);
    sumadd_fast(l[1]);
    muladd(n1, SECP256K1_N_C_0);
    muladd(n0, SECP256K1_N_C_1);
    extract(m1);
    sumadd(l[2]);
    muladd(n2, SECP256K1_N_C_0);
    muladd(n1, SECP256K1_N_C_1);
    sumadd(n0);
    extract(m2);
    sumadd(l[3]);
    muladd(n3, SECP256K1_N_C_0);
    muladd(n2, SECP256K1_N_C_1);
    sumadd(n1);
    extract(m3);
    muladd(n3, SECP256K1_N_C_1);
    sumadd(n2);
    extract(m4);
    sumadd_fast(n3);
    extract_fast(m5);
    VERIFY_CHECK(c0 <= 1);
    m6 = c0;

    /* Reduce 385 bits into 258. */
    /* p[0..4] = m[0..3] + m[4..6] * SECP256K1_N_C. */
    c0 = m0; c1 = 0; c2 = 0;
    muladd_fast(m4, SECP256K1_N_C_0);
    extract_fast(p0);
    sumadd_fast(m1);
    muladd(m5, SECP256K1_N_C_0);
    muladd(m4, SECP256K1_N_C_1);
    extract(p1);
    sumadd(m2);
    muladd(m6, SECP256K1_N_C_0);
    muladd(m5, SECP256K1_N_C_1);
    sumadd(m4);
    extract(p2);
    sumadd_fast(m3);
    muladd_fast(m6, SECP256K1_N_C_1);
    sumadd_fast(m5);
    extract_fast(p3);
    p4 = c0 + m6;
    VERIFY_CHECK(p4 <= 2);

    /* Reduce 258 bits into 256. */
    /* r[0..3] = p[0..3] + p[4] * SECP256K1_N_C. */
    c = p0 + (uint128_t)SECP256K1_N_C_0 * p4;
    r->d[0] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
    c += p1 + (uint128_t)SECP256K1_N_C_1 * p4;
    r->d[1] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
    c += p2 + (uint128_t)p4;
    r->d[2] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
    c += p3;
    r->d[3] = c & 0xFFFFFFFFFFFFFFFFULL; c >>= 64;
#endif

    /* Final reduction of r. */
    secp256k1_scalar_reduce(r, c + secp256k1_scalar_check_overflow(r));
}

static void secp256k1_scalar_mul_512(uint64_t l[8], const secp256k1_scalar *a, const secp256k1_scalar *b) {
#ifdef USE_ASM_X86_64
    const uint64_t *pb = b->d;
    __asm__ __volatile__(
    /* Preload */
    "movq 0(%%rdi), %%r15\n"
    "movq 8(%%rdi), %%rbx\n"
    "movq 16(%%rdi), %%rcx\n"
    "movq 0(%%rdx), %%r11\n"
    "movq 8(%%rdx), %%r12\n"
    "movq 16(%%rdx), %%r13\n"
    "movq 24(%%rdx), %%r14\n"
    /* (rax,rdx) = a0 * b0 */
    "movq %%r15, %%rax\n"
    "mulq %%r11\n"
    /* Extract l0 */
    "movq %%rax, 0(%%rsi)\n"
    /* (r8,r9,r10) = (rdx) */
    "movq %%rdx, %%r8\n"
    "xorq %%r9, %%r9\n"
    "xorq %%r10, %%r10\n"
    /* (r8,r9,r10) += a0 * b1 */
    "movq %%r15, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* (r8,r9,r10) += a1 * b0 */
    "movq %%rbx, %%rax\n"
    "mulq %%r11\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* Extract l1 */
    "movq %%r8, 8(%%rsi)\n"
    "xorq %%r8, %%r8\n"
    /* (r9,r10,r8) += a0 * b2 */
    "movq %%r15, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* (r9,r10,r8) += a1 * b1 */
    "movq %%rbx, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* (r9,r10,r8) += a2 * b0 */
    "movq %%rcx, %%rax\n"
    "mulq %%r11\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* Extract l2 */
    "movq %%r9, 16(%%rsi)\n"
    "xorq %%r9, %%r9\n"
    /* (r10,r8,r9) += a0 * b3 */
    "movq %%r15, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* Preload a3 */
    "movq 24(%%rdi), %%r15\n"
    /* (r10,r8,r9) += a1 * b2 */
    "movq %%rbx, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r10,r8,r9) += a2 * b1 */
    "movq %%rcx, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r10,r8,r9) += a3 * b0 */
    "movq %%r15, %%rax\n"
    "mulq %%r11\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* Extract l3 */
    "movq %%r10, 24(%%rsi)\n"
    "xorq %%r10, %%r10\n"
    /* (r8,r9,r10) += a1 * b3 */
    "movq %%rbx, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* (r8,r9,r10) += a2 * b2 */
    "movq %%rcx, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* (r8,r9,r10) += a3 * b1 */
    "movq %%r15, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* Extract l4 */
    "movq %%r8, 32(%%rsi)\n"
    "xorq %%r8, %%r8\n"
    /* (r9,r10,r8) += a2 * b3 */
    "movq %%rcx, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* (r9,r10,r8) += a3 * b2 */
    "movq %%r15, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* Extract l5 */
    "movq %%r9, 40(%%rsi)\n"
    /* (r10,r8) += a3 * b3 */
    "movq %%r15, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    /* Extract l6 */
    "movq %%r10, 48(%%rsi)\n"
    /* Extract l7 */
    "movq %%r8, 56(%%rsi)\n"
    : "+d"(pb)
    : "S"(l), "D"(a->d)
    : "rax", "rbx", "rcx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15", "cc", "memory");
#else
    /* 160 bit accumulator. */
    uint64_t c0 = 0, c1 = 0;
    uint32_t c2 = 0;

    /* l[0..7] = a[0..3] * b[0..3]. */
    muladd_fast(a->d[0], b->d[0]);
    extract_fast(l[0]);
    muladd(a->d[0], b->d[1]);
    muladd(a->d[1], b->d[0]);
    extract(l[1]);
    muladd(a->d[0], b->d[2]);
    muladd(a->d[1], b->d[1]);
    muladd(a->d[2], b->d[0]);
    extract(l[2]);
    muladd(a->d[0], b->d[3]);
    muladd(a->d[1], b->d[2]);
    muladd(a->d[2], b->d[1]);
    muladd(a->d[3], b->d[0]);
    extract(l[3]);
    muladd(a->d[1], b->d[3]);
    muladd(a->d[2], b->d[2]);
    muladd(a->d[3], b->d[1]);
    extract(l[4]);
    muladd(a->d[2], b->d[3]);
    muladd(a->d[3], b->d[2]);
    extract(l[5]);
    muladd_fast(a->d[3], b->d[3]);
    extract_fast(l[6]);
    VERIFY_CHECK(c1 == 0);
    l[7] = c0;
#endif
}

static void secp256k1_scalar_sqr_512(uint64_t l[8], const secp256k1_scalar *a) {
#ifdef USE_ASM_X86_64
    __asm__ __volatile__(
    /* Preload */
    "movq 0(%%rdi), %%r11\n"
    "movq 8(%%rdi), %%r12\n"
    "movq 16(%%rdi), %%r13\n"
    "movq 24(%%rdi), %%r14\n"
    /* (rax,rdx) = a0 * a0 */
    "movq %%r11, %%rax\n"
    "mulq %%r11\n"
    /* Extract l0 */
    "movq %%rax, 0(%%rsi)\n"
    /* (r8,r9,r10) = (rdx,0) */
    "movq %%rdx, %%r8\n"
    "xorq %%r9, %%r9\n"
    "xorq %%r10, %%r10\n"
    /* (r8,r9,r10) += 2 * a0 * a1 */
    "movq %%r11, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* Extract l1 */
    "movq %%r8, 8(%%rsi)\n"
    "xorq %%r8, %%r8\n"
    /* (r9,r10,r8) += 2 * a0 * a2 */
    "movq %%r11, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* (r9,r10,r8) += a1 * a1 */
    "movq %%r12, %%rax\n"
    "mulq %%r12\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* Extract l2 */
    "movq %%r9, 16(%%rsi)\n"
    "xorq %%r9, %%r9\n"
    /* (r10,r8,r9) += 2 * a0 * a3 */
    "movq %%r11, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* (r10,r8,r9) += 2 * a1 * a2 */
    "movq %%r12, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    "adcq $0, %%r9\n"
    /* Extract l3 */
    "movq %%r10, 24(%%rsi)\n"
    "xorq %%r10, %%r10\n"
    /* (r8,r9,r10) += 2 * a1 * a3 */
    "movq %%r12, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* (r8,r9,r10) += a2 * a2 */
    "movq %%r13, %%rax\n"
    "mulq %%r13\n"
    "addq %%rax, %%r8\n"
    "adcq %%rdx, %%r9\n"
    "adcq $0, %%r10\n"
    /* Extract l4 */
    "movq %%r8, 32(%%rsi)\n"
    "xorq %%r8, %%r8\n"
    /* (r9,r10,r8) += 2 * a2 * a3 */
    "movq %%r13, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    "addq %%rax, %%r9\n"
    "adcq %%rdx, %%r10\n"
    "adcq $0, %%r8\n"
    /* Extract l5 */
    "movq %%r9, 40(%%rsi)\n"
    /* (r10,r8) += a3 * a3 */
    "movq %%r14, %%rax\n"
    "mulq %%r14\n"
    "addq %%rax, %%r10\n"
    "adcq %%rdx, %%r8\n"
    /* Extract l6 */
    "movq %%r10, 48(%%rsi)\n"
    /* Extract l7 */
    "movq %%r8, 56(%%rsi)\n"
    :
    : "S"(l), "D"(a->d)
    : "rax", "rdx", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "cc", "memory");
#else
    /* 160 bit accumulator. */
    uint64_t c0 = 0, c1 = 0;
    uint32_t c2 = 0;

    /* l[0..7] = a[0..3] * b[0..3]. */
    muladd_fast(a->d[0], a->d[0]);
    extract_fast(l[0]);
    muladd2(a->d[0], a->d[1]);
    extract(l[1]);
    muladd2(a->d[0], a->d[2]);
    muladd(a->d[1], a->d[1]);
    extract(l[2]);
    muladd2(a->d[0], a->d[3]);
    muladd2(a->d[1], a->d[2]);
    extract(l[3]);
    muladd2(a->d[1], a->d[3]);
    muladd(a->d[2], a->d[2]);
    extract(l[4]);
    muladd2(a->d[2], a->d[3]);
    extract(l[5]);
    muladd_fast(a->d[3], a->d[3]);
    extract_fast(l[6]);
    VERIFY_CHECK(c1 == 0);
    l[7] = c0;
#endif
}

#undef sumadd
#undef sumadd_fast
#undef muladd
#undef muladd_fast
#undef muladd2
#undef extract
#undef extract_fast

static void secp256k1_scalar_mul(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b) {
    uint64_t l[8];
    secp256k1_scalar_mul_512(l, a, b);
    secp256k1_scalar_reduce_512(r, l);
}

static int secp256k1_scalar_shr_int(secp256k1_scalar *r, int n) {
    int ret;
    VERIFY_CHECK(n > 0);
    VERIFY_CHECK(n < 16);
    ret = r->d[0] & ((1 << n) - 1);
    r->d[0] = (r->d[0] >> n) + (r->d[1] << (64 - n));
    r->d[1] = (r->d[1] >> n) + (r->d[2] << (64 - n));
    r->d[2] = (r->d[2] >> n) + (r->d[3] << (64 - n));
    r->d[3] = (r->d[3] >> n);
    return ret;
}

static void secp256k1_scalar_sqr(secp256k1_scalar *r, const secp256k1_scalar *a) {
    uint64_t l[8];
    secp256k1_scalar_sqr_512(l, a);
    secp256k1_scalar_reduce_512(r, l);
}

#ifdef USE_ENDOMORPHISM
static void secp256k1_scalar_split_128(secp256k1_scalar *r1, secp256k1_scalar *r2, const secp256k1_scalar *a) {
    r1->d[0] = a->d[0];
    r1->d[1] = a->d[1];
    r1->d[2] = 0;
    r1->d[3] = 0;
    r2->d[0] = a->d[2];
    r2->d[1] = a->d[3];
    r2->d[2] = 0;
    r2->d[3] = 0;
}
#endif

SECP256K1_INLINE static int secp256k1_scalar_eq(const secp256k1_scalar *a, const secp256k1_scalar *b) {
    return ((a->d[0] ^ b->d[0]) | (a->d[1] ^ b->d[1]) | (a->d[2] ^ b->d[2]) | (a->d[3] ^ b->d[3])) == 0;
}

SECP256K1_INLINE static void secp256k1_scalar_mul_shift_var(secp256k1_scalar *r, const secp256k1_scalar *a, const secp256k1_scalar *b, unsigned int shift) {
    uint64_t l[8];
    unsigned int shiftlimbs;
    unsigned int shiftlow;
    unsigned int shifthigh;
    VERIFY_CHECK(shift >= 256);
    secp256k1_scalar_mul_512(l, a, b);
    shiftlimbs = shift >> 6;
    shiftlow = shift & 0x3F;
    shifthigh = 64 - shiftlow;
    r->d[0] = shift < 512 ? (l[0 + shiftlimbs] >> shiftlow | (shift < 448 && shiftlow ? (l[1 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[1] = shift < 448 ? (l[1 + shiftlimbs] >> shiftlow | (shift < 384 && shiftlow ? (l[2 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[2] = shift < 384 ? (l[2 + shiftlimbs] >> shiftlow | (shift < 320 && shiftlow ? (l[3 + shiftlimbs] << shifthigh) : 0)) : 0;
    r->d[3] = shift < 320 ? (l[3 + shiftlimbs] >> shiftlow) : 0;
    secp256k1_scalar_cadd_bit(r, 0, (l[(shift - 1) >> 6] >> ((shift - 1) & 0x3f)) & 1);
}

static SECP256K1_INLINE void secp256k1_scalar_cmov(secp256k1_scalar *r, const secp256k1_scalar *a, int flag) {
    uint64_t mask0, mask1;
    VG_CHECK_VERIFY(r->d, sizeof(r->d));
    mask0 = flag + ~((uint64_t)0);
    mask1 = ~mask0;
    r->d[0] = (r->d[0] & mask0) | (a->d[0] & mask1);
    r->d[1] = (r->d[1] & mask0) | (a->d[1] & mask1);
    r->d[2] = (r->d[2] & mask0) | (a->d[2] & mask1);
    r->d[3] = (r->d[3] & mask0) | (a->d[3] & mask1);
}

static const secp256k1_scalar SECP256K1_SCALAR_NEG_TWO_POW_256 = SECP256K1_SCALAR_CONST(
    0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFFUL, 0xFFFFFFFDUL,
    0x755DB9CDUL, 0x5E914077UL, 0x7FA4BD19UL, 0xA06C8282UL
);

static const secp256k1_scalar SECP256K1_SCALAR_TWO_POW_744 = SECP256K1_SCALAR_CONST(
    0x4E165355UL, 0x5D800C18UL, 0xEF116DB1UL, 0xB31347F1UL,
    0x6D77C2DCUL, 0x0E3E8029UL, 0x59BA208FUL, 0xFD01F4F7UL
);

static void secp256k1_scalar_mul_add(int64_t a0, int64_t a1, int64_t b0, int64_t b1, int64_t c0, int64_t c1, int64_t d0, int64_t d1, int64_t *t) {

    /*  Each [a0,a1], etc. pair is a 126-bit signed value e.g. a0 + a1 * 2^64.
     *  This method calculates ([a0,a1] * [c0,c1]) + ([b0,b1] * [d0,d1]), and
     *  writes the 252-bit signed result to [t[0],t[1],t[2],t[3]].
     */

    int64_t z0, z1, z2, z3;
    int128_t tt;

    tt  = (int128_t)a0 * b0
        + (int128_t)c0 * d0;
    z0  = (int64_t)tt; tt -= z0; tt >>= 64;

    tt += (int128_t)a0 * b1
        + (int128_t)a1 * b0
        + (int128_t)c0 * d1
        + (int128_t)c1 * d0;
    z1  = (int64_t)tt; tt -= z1; tt >>= 64;

    tt += (int128_t)a1 * b1
        + (int128_t)c1 * d1;
    z2  = (int64_t)tt; tt -= z2; tt >>= 64;

    z3 = (int64_t)tt;

    t[0] = z0; t[1] = z1; t[2] = z2; t[3] = z3;
}

static void secp256k1_scalar_combine_1s(int64_t *t) {

    int64_t a = t[0], b = t[1], c = t[2], d = t[3],
            e = t[4], f = t[5], g = t[6], h = t[7];
    int128_t I, J, K, L;

    I = (int128_t)e * a + (int128_t)f * c;
    J = (int128_t)e * b + (int128_t)f * d;
    K = (int128_t)g * a + (int128_t)h * c;
    L = (int128_t)g * b + (int128_t)h * d;

    a = (int64_t)I; I -= a; I >>= 64; b = (int64_t)I;
    c = (int64_t)J; J -= c; J >>= 64; d = (int64_t)J;
    e = (int64_t)K; K -= e; K >>= 64; f = (int64_t)K;
    g = (int64_t)L; L -= g; L >>= 64; h = (int64_t)L;

    t[0] = a; t[1] = b; t[2] = c; t[3] = d;
    t[4] = e; t[5] = f; t[6] = g; t[7] = h;
}

static void secp256k1_scalar_combine_2s(int64_t *t) {

    int64_t a0 = t[ 0], a1 = t[ 1];
    int64_t b0 = t[ 2], b1 = t[ 3];
    int64_t c0 = t[ 4], c1 = t[ 5];
    int64_t d0 = t[ 6], d1 = t[ 7];
    int64_t e0 = t[ 8], e1 = t[ 9];
    int64_t f0 = t[10], f1 = t[11];
    int64_t g0 = t[12], g1 = t[13];
    int64_t h0 = t[14], h1 = t[15];

    secp256k1_scalar_mul_add(e0, e1, a0, a1, f0, f1, c0, c1, &t[0]);
    secp256k1_scalar_mul_add(e0, e1, b0, b1, f0, f1, d0, d1, &t[4]);
    secp256k1_scalar_mul_add(g0, g1, a0, a1, h0, h1, c0, c1, &t[8]);
    secp256k1_scalar_mul_add(g0, g1, b0, b1, h0, h1, d0, d1, &t[12]);
}

static void secp256k1_scalar_decode_matrix(secp256k1_scalar *r, int64_t *t) {

    uint64_t r0, r1, r2, r3;
    int flag;
    secp256k1_scalar u;
    int128_t cc;

    cc  = t[0];
    r0 = (uint64_t)cc; cc >>= 64;
    cc += t[1];
    r1 = (uint64_t)cc; cc >>= 64;
    cc += t[2];
    r2 = (uint64_t)cc; cc >>= 64;
    cc += t[3];
    r3 = (uint64_t)cc; cc >>= 64;

    VERIFY_CHECK(cc == 0 || cc == -1);

    flag = (int)cc & 1;

    r->d[0] = r0;
    r->d[1] = r1;
    r->d[2] = r2;
    r->d[3] = r3;

    secp256k1_scalar_add(&u, r, &SECP256K1_SCALAR_NEG_TWO_POW_256);
    secp256k1_scalar_cmov(r, &u, flag);
}

static void secp256k1_scalar_encode_62(int64_t *r, const secp256k1_scalar *a) {

    const uint64_t M62 = UINT64_MAX >> 2;
    const uint64_t *d = &a->d[0];
    uint64_t a0 = d[0], a1 = d[1], a2 = d[2], a3 = d[3];

#ifdef VERIFY
    VERIFY_CHECK(secp256k1_scalar_check_overflow(a) == 0);
#endif

    r[0] =  a0                   & M62;
    r[1] = (a0 >> 62 | a1 <<  2) & M62;
    r[2] = (a1 >> 60 | a2 <<  4) & M62;
    r[3] = (a2 >> 58 | a3 <<  6) & M62;
    r[4] =  a3 >> 56;

#ifdef VERIFY
    VERIFY_CHECK(secp256k1_scalar_check_overflow(a) == 0);
#endif
}

static int secp256k1_scalar_divsteps_62(uint16_t eta, uint64_t f0, uint64_t g0, int64_t *t) {

    uint64_t u = -(uint64_t)1, v = 0, q = 0, r = -(uint64_t)1;
    uint64_t c1, c2, f = f0, g = g0, x, y, z;
    int i;

    for (i = 0; i < 62; ++i) {

        VERIFY_CHECK((f & 1) == 1);
        VERIFY_CHECK((u * f0 + v * g0) == -f << i);
        VERIFY_CHECK((q * f0 + r * g0) == -g << i);

        c1 = -(g & (eta >> 15));

        x = (f ^ g) & c1;
        f ^= x; g ^= x; g ^= c1; g -= c1;

        y = (u ^ q) & c1;
        u ^= y; q ^= y; q ^= c1; q -= c1;

        z = (v ^ r) & c1;
        v ^= z; r ^= z; r ^= c1; r -= c1;

        eta = (eta ^ (uint16_t)c1) - (uint16_t)c1 - 1;

        c2 = -(g & 1);

        g += (f & c2); g >>= 1;
        q += (u & c2); u <<= 1;
        r += (v & c2); v <<= 1;
    }

    t[0] = (int64_t)u;
    t[1] = (int64_t)v;
    t[2] = (int64_t)q;
    t[3] = (int64_t)r;

    return eta;
}

static void secp256k1_scalar_update_fg(int len, int64_t *f, int64_t *g, int64_t *t) {

    const int64_t M62 = (int64_t)(UINT64_MAX >> 2);
    int64_t u = t[0], v = t[1], q = t[2], r = t[3], fi, gi;
    int128_t cf = 0, cg = 0;
    int i;

    VERIFY_CHECK(len > 0);

    fi = f[0];
    gi = g[0];

    cf -= (int128_t)u * fi + (int128_t)v * gi;
    cg -= (int128_t)q * fi + (int128_t)r * gi;

    VERIFY_CHECK(((int64_t)cf & M62) == 0);
    VERIFY_CHECK(((int64_t)cg & M62) == 0);

    cf >>= 62;
    cg >>= 62;

    for (i = 1; i < len; ++i) {

        fi = f[i];
        gi = g[i];

        cf -= (int128_t)u * fi + (int128_t)v * gi;
        cg -= (int128_t)q * fi + (int128_t)r * gi;

        f[i - 1] = (int64_t)cf & M62; cf >>= 62;
        g[i - 1] = (int64_t)cg & M62; cg >>= 62;
    }

    f[i - 1] = (int64_t)cf;
    g[i - 1] = (int64_t)cg;
}

static void secp256k1_scalar_inverse(secp256k1_scalar *r, const secp256k1_scalar *x) {
#if defined(EXHAUSTIVE_TEST_ORDER)
    int i;
    *r = 0;
    for (i = 0; i < EXHAUSTIVE_TEST_ORDER; i++)
        if ((i * *x) % EXHAUSTIVE_TEST_ORDER == 1)
            *r = i;
    /* If this VERIFY_CHECK triggers we were given a noninvertible scalar (and thus
     * have a composite group order; fix it in exhaustive_tests.c). */
    VERIFY_CHECK(*r != 0);
}
#elif 1

    /* Modular inversion based on the paper "Fast constant-time gcd computation and
     * modular inversion" by Daniel J. Bernstein and Bo-Yin Yang.
     */

    int64_t t[12 * 4];
    int64_t f[5] = { 0x3FD25E8CD0364141LL, 0x2ABB739ABD2280EELL, 0x3FFFFFFFFFFFFFEBLL,
        0x3FFFFFFFFFFFFFFFLL, 0xFFLL };
    int64_t g[5];
    secp256k1_scalar b0, d0, a1, b1, c1, d1;
    int i, len, sign;
    int16_t eta;
#ifdef VERIFY
    int zero_in = secp256k1_scalar_is_zero(x);
#endif

    /* Instead of dividing the output by 2^744, scale the input. */
    secp256k1_scalar_mul(&b0, x, &SECP256K1_SCALAR_TWO_POW_744);
    secp256k1_scalar_encode_62(&g[0], &b0);

    /* The paper uses 'delta'; eta == -delta (a performance tweak). */
    eta = -1;

    for (i = 0; i < 12; ++i) {
        eta = secp256k1_scalar_divsteps_62(eta, f[0], g[0], &t[i * 4]);
        len = i <= 6 ? 5 : i >= 10 ? 1 : 11 - i;
        secp256k1_scalar_update_fg(len, f, g, &t[i * 4]);
    }

    /* At this point sufficient iterations have been performed that g must have reached 0
     * and (if g was not originally 0) f must now equal +/- GCD of the initial f, g
     * values i.e. +/- 1. The matrix outputs from each _divstep_62 are combined to get the
     * Bézout coefficients, and thus the modular inverse. The matrix outputs of
     * _divstep_62 introduce an extra factor of 2^62 each, so there is a total extra
     * factor of 2^744 to account for (by scaling the input and/or output accordingly).
     */

    VERIFY_CHECK(g[0] == 0);

    sign = (f[0] >> 1) & 1;

    for (i = 0; i < 3; ++i) {
        int tOff = i * 16;
        secp256k1_scalar_combine_1s(&t[tOff + 0]);
        secp256k1_scalar_combine_1s(&t[tOff + 8]);
        secp256k1_scalar_combine_2s(&t[tOff + 0]);
    }

    /* secp256k1_scalar_decode_matrix(&a0, &t[0]); */
    secp256k1_scalar_decode_matrix(&b0, &t[4]);
    /* secp256k1_scalar_decode_matrix(&c0, &t[8]); */
    secp256k1_scalar_decode_matrix(&d0, &t[12]);

    secp256k1_scalar_decode_matrix(&a1, &t[16]);
    secp256k1_scalar_decode_matrix(&b1, &t[20]);
    secp256k1_scalar_decode_matrix(&c1, &t[24]);
    secp256k1_scalar_decode_matrix(&d1, &t[28]);

    secp256k1_scalar_mul(&a1, &a1, &b0);
    secp256k1_scalar_mul(&b1, &b1, &d0);
    secp256k1_scalar_mul(&c1, &c1, &b0);
    secp256k1_scalar_mul(&d1, &d1, &d0);

    secp256k1_scalar_add(&b0, &a1, &b1);
    secp256k1_scalar_add(&d0, &c1, &d1);

    secp256k1_scalar_decode_matrix(&a1, &t[32]);
    secp256k1_scalar_decode_matrix(&b1, &t[36]);
    /* secp256k1_scalar_decode_matrix(&c1, &t[40]); */
    /* secp256k1_scalar_decode_matrix(&d1, &t[44]); */

    secp256k1_scalar_mul(&a1, &a1, &b0);
    secp256k1_scalar_mul(&b1, &b1, &d0);
    /* secp256k1_scalar_mul(&c1, &c1, &b0); */
    /* secp256k1_scalar_mul(&d1, &d1, &d0); */

    secp256k1_scalar_add(&b0, &a1, &b1);
    /* secp256k1_scalar_add(&d0, &c1, &d1); */

    secp256k1_scalar_cond_negate(&b0, sign);

#ifdef VERIFY
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&b0) == !zero_in);
#endif

    *r = b0;
}

SECP256K1_INLINE static int secp256k1_scalar_is_even(const secp256k1_scalar *a) {
    return !(a->d[0] & 1);
}
#else
    secp256k1_scalar *t;
    int i;
    /* First compute xN as x ^ (2^N - 1) for some values of N,
     * and uM as x ^ M for some values of M. */
    secp256k1_scalar x2, x3, x6, x8, x14, x28, x56, x112, x126;
    secp256k1_scalar u2, u5, u9, u11, u13;

    secp256k1_scalar_sqr(&u2, x);
    secp256k1_scalar_mul(&x2, &u2,  x);
    secp256k1_scalar_mul(&u5, &u2, &x2);
    secp256k1_scalar_mul(&x3, &u5,  &u2);
    secp256k1_scalar_mul(&u9, &x3, &u2);
    secp256k1_scalar_mul(&u11, &u9, &u2);
    secp256k1_scalar_mul(&u13, &u11, &u2);

    secp256k1_scalar_sqr(&x6, &u13);
    secp256k1_scalar_sqr(&x6, &x6);
    secp256k1_scalar_mul(&x6, &x6, &u11);

    secp256k1_scalar_sqr(&x8, &x6);
    secp256k1_scalar_sqr(&x8, &x8);
    secp256k1_scalar_mul(&x8, &x8,  &x2);

    secp256k1_scalar_sqr(&x14, &x8);
    for (i = 0; i < 5; i++) {
        secp256k1_scalar_sqr(&x14, &x14);
    }
    secp256k1_scalar_mul(&x14, &x14, &x6);

    secp256k1_scalar_sqr(&x28, &x14);
    for (i = 0; i < 13; i++) {
        secp256k1_scalar_sqr(&x28, &x28);
    }
    secp256k1_scalar_mul(&x28, &x28, &x14);

    secp256k1_scalar_sqr(&x56, &x28);
    for (i = 0; i < 27; i++) {
        secp256k1_scalar_sqr(&x56, &x56);
    }
    secp256k1_scalar_mul(&x56, &x56, &x28);

    secp256k1_scalar_sqr(&x112, &x56);
    for (i = 0; i < 55; i++) {
        secp256k1_scalar_sqr(&x112, &x112);
    }
    secp256k1_scalar_mul(&x112, &x112, &x56);

    secp256k1_scalar_sqr(&x126, &x112);
    for (i = 0; i < 13; i++) {
        secp256k1_scalar_sqr(&x126, &x126);
    }
    secp256k1_scalar_mul(&x126, &x126, &x14);

    /* Then accumulate the final result (t starts at x126). */
    t = &x126;
    for (i = 0; i < 3; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 5; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 5; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 6; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 3; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 5; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 000 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u5); /* 101 */
    for (i = 0; i < 10; i++) { /* 0000000 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 4; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x3); /* 111 */
    for (i = 0; i < 9; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x8); /* 11111111 */
    for (i = 0; i < 5; i++) { /* 0 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u11); /* 1011 */
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 5; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &x2); /* 11 */
    for (i = 0; i < 6; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 10; i++) { /* 000000 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u13); /* 1101 */
    for (i = 0; i < 4; i++) {
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, &u9); /* 1001 */
    for (i = 0; i < 6; i++) { /* 00000 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(t, t, x); /* 1 */
    for (i = 0; i < 8; i++) { /* 00 */
        secp256k1_scalar_sqr(t, t);
    }
    secp256k1_scalar_mul(r, t, &x6); /* 111111 */
}

SECP256K1_INLINE static int secp256k1_scalar_is_even(const secp256k1_scalar *a) {
    return !(a->d[0] & 1);
}
#endif

#endif /* SECP256K1_SCALAR_REPR_IMPL_H */
