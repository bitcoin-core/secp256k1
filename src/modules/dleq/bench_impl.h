/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_DLEQ_BENCH_H
#define SECP256K1_MODULE_DLEQ_BENCH_H

#include "../../../include/secp256k1_dleq.h"

typedef struct {
    secp256k1_context *ctx;

    /* inputs */
    unsigned char *seckeys;       /* iters * 32 bytes */
    secp256k1_pubkey *pubkeys_A;
    secp256k1_pubkey *pubkeys_B;
    unsigned char aux_rand[32];
    unsigned char msg[32];

    /* outputs of proving, inputs of verification */
    unsigned char *proofs;        /* iters * 64 bytes */
    secp256k1_pubkey *pubkeys_C;
} bench_dleq_data;

static void bench_dleq_prove(void *arg, int iters) {
    bench_dleq_data *data = (bench_dleq_data *)arg;
    int i;

    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_dleq_prove(data->ctx, &data->proofs[i * 64], &data->pubkeys_C[i],
                                   &data->seckeys[i * 32], &data->pubkeys_B[i], data->aux_rand, data->msg));
    }
}

static void bench_dleq_verify(void *arg, int iters) {
    bench_dleq_data *data = (bench_dleq_data *)arg;
    int i;

    for (i = 0; i < iters; i++) {
        CHECK(secp256k1_dleq_verify(data->ctx, &data->proofs[i * 64], &data->pubkeys_A[i],
                                    &data->pubkeys_B[i], &data->pubkeys_C[i], data->msg));
    }
}

static void run_dleq_bench(int iters, int argc, char **argv) {
    int i;
    bench_dleq_data data;
    int d = argc == 1;

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    data.seckeys = malloc(iters * 32);
    data.pubkeys_A = malloc(iters * sizeof(secp256k1_pubkey));
    data.pubkeys_B = malloc(iters * sizeof(secp256k1_pubkey));
    data.proofs = malloc(iters * 64);
    data.pubkeys_C = malloc(iters * sizeof(secp256k1_pubkey));
    memset(data.aux_rand, 'a', 32);
    memset(data.msg, 'm', 32);

    for (i = 0; i < iters; i++) {
        unsigned char *sk = &data.seckeys[i * 32];
        unsigned char sk_B[32];
        secp256k1_write_be32(sk, i);
        secp256k1_write_be32(sk_B, i);
        memset(&sk[4], 's', 28);
        memset(&sk_B[4], 'b', 28);
        CHECK(secp256k1_ec_pubkey_create(data.ctx, &data.pubkeys_A[i], sk));
        CHECK(secp256k1_ec_pubkey_create(data.ctx, &data.pubkeys_B[i], sk_B));
    }
    /* Generate the proofs (and C points) up front, so that verification can
     * also be benchmarked on its own. The prove benchmark overwrites them
     * with the same values, as proving is deterministic. */
    bench_dleq_prove(&data, iters);

    if (d || have_flag(argc, argv, "dleq") || have_flag(argc, argv, "dleq_prove")) run_benchmark("dleq_prove", bench_dleq_prove, NULL, NULL, (void *) &data, 10, iters);
    if (d || have_flag(argc, argv, "dleq") || have_flag(argc, argv, "dleq_verify")) run_benchmark("dleq_verify", bench_dleq_verify, NULL, NULL, (void *) &data, 10, iters);

    free(data.seckeys);
    free(data.pubkeys_A);
    free(data.pubkeys_B);
    free(data.proofs);
    free(data.pubkeys_C);
    secp256k1_context_destroy(data.ctx);
}

#endif /* SECP256K1_MODULE_DLEQ_BENCH_H */
