/***********************************************************************
 * Copyright (c) 2020 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SELFTEST_H
#define SECP256K1_SELFTEST_H

#include "hash.h"

#include <string.h>

static int secp256k1_selftest_sha256(void) {
    static const char *input63 = "For this sample, this 63-byte string will be used as input data";
    static const unsigned char output32[32] = {
        0xf0, 0x8a, 0x78, 0xcb, 0xba, 0xee, 0x08, 0x2b, 0x05, 0x2a, 0xe0, 0x70, 0x8f, 0x32, 0xfa, 0x1e,
        0x50, 0xc5, 0xc4, 0x21, 0xaa, 0x77, 0x2b, 0xa5, 0xdb, 0xb4, 0x06, 0xa2, 0xea, 0x6b, 0xe3, 0x42,
    };
    unsigned char out[32];
    secp256k1_sha256 hasher;
    secp256k1_sha256_initialize(&hasher);
    secp256k1_sha256_write(&hasher, (const unsigned char*)input63, 63);
    secp256k1_sha256_finalize(&hasher, out);
    return secp256k1_memcmp_var(out, output32, 32) == 0;
}

static int secp256k1_selftest_cpuid(void) {
    int ret = 1;

#if defined(USE_ASM_X86_64)
    /* getting the CPU flags from the cpu, more information in the Intel manual,
     * Table 3-8 Information Returned by CPUID instruction (3-194, Vol.2A)
     */
    const int CPU_FLAG_ENUMERATION = 7;
    const int LEAF_NODE_ZERO = 0;

    /* for the cpu self test, we need BMI2 and ADX support */
    const int BIT_ADX = 19;
    const int BIT_BMI2 = 8;
    int flags = 0;
    int has_adx = 0;
    int has_bmi2 = 0;
    __asm__ __volatile__("cpuid\n"
                       : "=b"(flags)
                       : "a"(CPU_FLAG_ENUMERATION), "c"(LEAF_NODE_ZERO)
                       : "rdx", "cc");

    has_adx = (flags >> BIT_ADX) & 1;
    has_bmi2 = (flags >> BIT_BMI2) & 1;
    ret = has_adx && has_bmi2;
#endif
    return ret;
}

static int secp256k1_selftest_passes(void) {
    return secp256k1_selftest_sha256();
}

#endif /* SECP256K1_SELFTEST_H */
