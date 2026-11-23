/***********************************************************************
 * Copyright (c) 2020 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SELFTEST_H
#define SECP256K1_SELFTEST_H

#include "hash.h"

#include <string.h>

/* Check that the compiler does not miscompile memcmp.
 *
 * GCC 9.2 to 9.5, 10.1 and 10.2 may stop comparing at the first zero
 * byte of a constant array when optimizing with -O2 or -O3, see
 * https://gcc.gnu.org/bugzilla/show_bug.cgi?id=95189 (fixed in GCC 10.3).
 * On affected compilers, building with -fno-builtin-memcmp works around
 * the bug.
 */
static int secp256k1_selftest_memcmp(void) {
    char a[] = "\0abc";
    /* volatile is required to trigger the bug. */
    volatile int res = memcmp(a, "\0\0\0\0", 4);
    return res != 0;
}

static int secp256k1_selftest_sha256(secp256k1_sha256_compression_function fn_compression) {
    secp256k1_hash_ctx hash_ctx;
    static const char *input63 = "For this sample, this 63-byte string will be used as input data";
    static const unsigned char output32[32] = {
        0xf0, 0x8a, 0x78, 0xcb, 0xba, 0xee, 0x08, 0x2b, 0x05, 0x2a, 0xe0, 0x70, 0x8f, 0x32, 0xfa, 0x1e,
        0x50, 0xc5, 0xc4, 0x21, 0xaa, 0x77, 0x2b, 0xa5, 0xdb, 0xb4, 0x06, 0xa2, 0xea, 0x6b, 0xe3, 0x42,
    };
    unsigned char out[32];
    secp256k1_sha256 hasher;
    secp256k1_sha256_initialize(&hasher);
    hash_ctx.fn_sha256_compression = fn_compression;
    secp256k1_sha256_write(&hash_ctx, &hasher, (const unsigned char*)input63, 63);
    secp256k1_sha256_finalize(&hash_ctx, &hasher, out);
    if (memcmp(out, output32, 32) != 0) {
        return 0;
    }
    if (fn_compression != secp256k1_sha256_transform && !secp256k1_sha256_smoke_test(fn_compression)) {
        return 0;
    }
    return 1;
}

static int secp256k1_selftest_passes(void) {
    return secp256k1_selftest_memcmp()
        /* Use default sha256 compression */
        && secp256k1_selftest_sha256(secp256k1_sha256_transform);
}

#endif /* SECP256K1_SELFTEST_H */
