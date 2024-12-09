/***********************************************************************
 * Copyright (c) 2015 Pieter Wuille, Andrew Poelstra                   *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_ECDH_BENCH_H
#define SECP256K1_MODULE_ECDH_BENCH_H

#include "../../../include/secp256k1_ecdh.h"

typedef struct {
    secp256k1_context *ctx;
    unsigned char point[33];
    unsigned char scalar[32];
} bench_ecdh_data;


/* Outputs a hash of the coordinates, but also updates data->point with the coordinates. */
static int ecdh_hash_function_bench(unsigned char* output, const unsigned char *x32, const unsigned char *y32, void* arg) {
    bench_ecdh_data* data = arg;
    int ret = secp256k1_ecdh_hash_function_sha256(output, x32, y32, NULL);
    data->point[0] ^= y32[17] & 1;
    memcpy(data->point + 1, x32, 32);
    return ret;
}

static int ecdh_xonly_hash_function_bench(unsigned char* output, const unsigned char *x32, void* arg) {
    bench_ecdh_data* data = arg;
    int ret = secp256k1_ecdh_xonly_hash_function_sha256(output, x32, NULL);
    memcpy(data->point + 1, x32, 32);
    return ret;
}

static void bench_ecdh_setup(void* arg) {
    int i;
    bench_ecdh_data *data = (bench_ecdh_data*)arg;
    static const unsigned char point[33] = {
        0x03,
        0x54, 0x94, 0xc1, 0x5d, 0x32, 0x09, 0x97, 0x06,
        0xc2, 0x39, 0x5f, 0x94, 0x34, 0x87, 0x45, 0xfd,
        0x75, 0x7c, 0xe3, 0x0e, 0x4e, 0x8c, 0x90, 0xfb,
        0xa2, 0xba, 0xd1, 0x84, 0xf8, 0x83, 0xc6, 0x9f
    };

    for (i = 0; i < 32; i++) {
        data->scalar[i] = i + 1;
    }
    memcpy(data->point, point, sizeof(point));
}

static void bench_ecdh(void* arg, int iters) {
    int i;
    bench_ecdh_data *data = (bench_ecdh_data*)arg;

    for (i = 0; i < iters; i++) {
        /* Compute point multiplication of data->point with data->scalar, and then update:
         * - data->scalar to be the computed shared secret (hash of point multiplication output)
         * - data->point to have X coordinate equal to X coordinate of point multiplication output,
         *   and optionally flipped Y coordinate. */
        secp256k1_pubkey pubkey;
        CHECK(secp256k1_ec_pubkey_parse(data->ctx, &pubkey, data->point, sizeof(data->point)) == 1);
        CHECK(secp256k1_ecdh(data->ctx, data->scalar, &pubkey, data->scalar, &ecdh_hash_function_bench, arg) == 1);
    }
}

static void bench_ecdh_xonly(void* arg, int iters) {
    int i;
    bench_ecdh_data *data = (bench_ecdh_data*)arg;

    for (i = 0; i < iters; i++) {
        /* Compute X-only point multiplication of data->point with data->scalar, and then update:
         * - data->scalar to be the computed shared secret (hash of point multiplication output X coordinate)
         * - data->point to have X coordinate equal to X coordinate of point multiplication output. */
        CHECK(secp256k1_ecdh_xonly(data->ctx, data->scalar, data->point + 1, data->scalar, &ecdh_xonly_hash_function_bench, arg) == 1);
    }
}

static void run_ecdh_bench(int iters, int argc, char** argv) {
    bench_ecdh_data data;
    int d = argc == 1;

    /* create a context with no capabilities */
    data.ctx = secp256k1_context_create(SECP256K1_FLAGS_TYPE_CONTEXT);

    if (d || have_flag(argc, argv, "ecdh")) run_benchmark("ecdh", bench_ecdh, bench_ecdh_setup, NULL, &data, 10, iters);
    if (d || have_flag(argc, argv, "ecdh") || have_flag(argc, argv, "ecdh_xonly")) run_benchmark("ecdh_xonly", bench_ecdh_xonly, bench_ecdh_setup, NULL, &data, 10, iters);

    secp256k1_context_destroy(data.ctx);
}

#endif /* SECP256K1_MODULE_ECDH_BENCH_H */
