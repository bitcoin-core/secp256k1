/**********************************************************************
 * Copyright (c) 2015 Pieter Wuille, Andrew Poelstra                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <string.h>

#include "include/secp256k1.h"
#include "util.h"
#include "bench.h"

typedef struct {
    unsigned char point[33];
    int pointlen;
    unsigned char scalar[32];
} bench_multiply_t;

static void bench_multiply_setup(void* arg) {
    int i;
    bench_multiply_t *data = (bench_multiply_t*)arg;
    const unsigned char point[] = {
        0x03,
        0x54, 0x94, 0xc1, 0x5d, 0x32, 0x09, 0x97, 0x06,
        0xc2, 0x39, 0x5f, 0x94, 0x34, 0x87, 0x45, 0xfd,
        0x75, 0x7c, 0xe3, 0x0e, 0x4e, 0x8c, 0x90, 0xfb,
        0xa2, 0xba, 0xd1, 0x84, 0xf8, 0x83, 0xc6, 0x9f
    };

    for (i = 0; i < 32; i++) data->scalar[i] = i + 1;
    data->pointlen = sizeof(point);
    memcpy(data->point, point, data->pointlen);
}

static void bench_multiply(void* arg) {
    int i;
    unsigned char res[32];
    bench_multiply_t *data = (bench_multiply_t*)arg;

    for (i = 0; i < 20000; i++) {
        CHECK(secp256k1_ecdh_xo(res, data->point+1, data->scalar) == 1);
    }
}

int main(void) {
    bench_multiply_t data;

    run_benchmark("ecdh_mult_xo", bench_multiply, bench_multiply_setup, NULL, &data, 10, 20000);
    return 0;
}
