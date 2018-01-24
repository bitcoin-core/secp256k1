/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include <string.h>

#include "include/secp256k1.h"
#include "include/secp256k1_aggsig.h"
#include "util.h"
#include "bench.h"

#define MAX_N_SIGNATURES 256

typedef struct {
    secp256k1_context *ctx;
    secp256k1_aggsig_context *aggctx;
    secp256k1_scratch_space *scratch;
    unsigned int n_signatures;
    unsigned char seckeys[MAX_N_SIGNATURES][32];
    secp256k1_pubkey pubkeys[MAX_N_SIGNATURES];
    secp256k1_aggsig_partial_signature partials[MAX_N_SIGNATURES];
    unsigned char msg[32];
    unsigned char sig[64];
} bench_aggsig_t;

void bench_aggsig(void* arg) {
    size_t i;
    bench_aggsig_t *data = (bench_aggsig_t*) arg;
    for (i = 0; i < 1000; i++) {
        CHECK(secp256k1_aggsig_verify(data->ctx, data->scratch, data->sig, data->msg, data->pubkeys, data->n_signatures));
    }
}

void bench_aggsig_setup(void* arg) {
    size_t i;
    unsigned char seed[32] = "this'll do for a seed i guess.";
    bench_aggsig_t *data = (bench_aggsig_t*) arg;
    for (i = 0; i < data->n_signatures; i++) {
        memcpy(&data->seckeys[i], seed, 32);
        data->seckeys[i][i%32] += i;
        CHECK(secp256k1_ec_pubkey_create(data->ctx, &data->pubkeys[i], data->seckeys[i]));
    }
    data->aggctx = secp256k1_aggsig_context_create(data->ctx, data->pubkeys, data->n_signatures, seed);

    for (i = 0; i < data->n_signatures; i++) {
        CHECK(secp256k1_aggsig_generate_nonce(data->ctx, data->aggctx, i));
    }
    for (i = 0; i < data->n_signatures; i++) {
        CHECK(secp256k1_aggsig_partial_sign(data->ctx, data->aggctx, &data->partials[i], data->msg, data->seckeys[i], i));
    }
    CHECK(secp256k1_aggsig_combine_signatures(data->ctx, data->aggctx, data->sig, data->partials));
}

void bench_aggsig_teardown(void* arg) {
    bench_aggsig_t *data = (bench_aggsig_t*) arg;
    secp256k1_aggsig_context_destroy(data->aggctx);
}

int main(int argc, char **argv) {
    int n_signatures = 32;
    bench_aggsig_t data;
    char str[32];

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 10000, 25000);
    if (argc > 1) {
        n_signatures = strtol(argv[1], NULL, 0);
    }
    if (n_signatures <= 0 || n_signatures > MAX_N_SIGNATURES) {
        n_signatures = 32;
    }
    data.n_signatures = (unsigned int) n_signatures;
    sprintf(str, "aggsig_%i", n_signatures);
    run_benchmark(str, bench_aggsig, bench_aggsig_setup, bench_aggsig_teardown, &data, 10, 1000);

    secp256k1_scratch_space_destroy(data.scratch);
    secp256k1_context_destroy(data.ctx);
    return 0;
}
