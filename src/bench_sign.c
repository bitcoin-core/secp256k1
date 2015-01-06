/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "include/secp256k1.h"
#include "util.h"
#include "bench.h"

typedef struct {
    unsigned char msg[32];
    unsigned char key[32];
} bench_sign_t;

static void bench_sign_setup(void* arg) {
    bench_sign_t *data = (bench_sign_t*)arg;

    for (int i = 0; i < 32; i++) data->msg[i] = i + 1;
    for (int i = 0; i < 32; i++) data->key[i] = i + 65;
}

static void bench_sign(void* arg, unsigned int iters) {
    bench_sign_t *data = (bench_sign_t*)arg;

    unsigned char sig[64];
    for (unsigned int i=0; i<iters; i++) {
        int recid = 0;
        CHECK(secp256k1_ecdsa_sign_compact(data->msg, sig, data->key, NULL, NULL, &recid));
        for (int j = 0; j < 32; j++) {
            data->msg[j] = sig[j];             /* Move former R to message. */
            data->key[j] = sig[j + 32];        /* Move former S to key.     */
        }
    }
}

int main(int argc, char **argv) {
    int iters=20000, count=10, tablesize=0;

    parse_bench_args(argc, argv, &iters, &count, &tablesize);

    secp256k1_start(SECP256K1_START_SIGN, tablesize);

    bench_sign_t data;
    run_benchmark(bench_sign, bench_sign_setup, NULL, &data, count, iters);

    secp256k1_stop();
    return 0;
}
