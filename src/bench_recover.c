/**********************************************************************
 * Copyright (c) 2014-2015 Pieter Wuille                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#include "include/secp256k1.h"
#include "include/secp256k1_recovery.h"
#include "util.h"
#include "bench.h"

#define RECOVER_AMOUNT 10
#define BREATHING_OFFSET 16

typedef struct {
    secp256k1_context *ctx;
    secp256k1_scratch_space *scratch;
    unsigned char msg[RECOVER_AMOUNT][32];
    const unsigned char *msgs_ptrs[RECOVER_AMOUNT];
    unsigned char sig[RECOVER_AMOUNT][64];
    secp256k1_ecdsa_signature sig_arr[RECOVER_AMOUNT];
    const secp256k1_ecdsa_signature* sigs_ptrs[RECOVER_AMOUNT];
    secp256k1_pubkey keys_arr[RECOVER_AMOUNT*4];
    size_t pubkeys_n[RECOVER_AMOUNT];
} bench_recover_data;

void bench_recover(void* arg) {
    int i;
    bench_recover_data *data = (bench_recover_data*)arg;
    secp256k1_pubkey pubkey;
    unsigned char pubkeyc[33];

    for (i = 0; i < 20000; i++) {
        int j;
        size_t pubkeylen = 33;
        secp256k1_ecdsa_recoverable_signature sig;
        CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(data->ctx, &sig, data->sig[0], i % 2));
        CHECK(secp256k1_ecdsa_recover(data->ctx, &pubkey, &sig, data->msg[0]));
        CHECK(secp256k1_ec_pubkey_serialize(data->ctx, pubkeyc, &pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED));
        for (j = 0; j < 32; j++) {
            data->sig[0][j + 32] = data->msg[0][j];    /* Move former message to S. */
            data->msg[0][j] = data->sig[0][j];         /* Move former R to message. */
            data->sig[0][j] = pubkeyc[j + 1];       /* Move recovered pubkey X coordinate to R (which must be a valid X coordinate). */
        }
      if (i < RECOVER_AMOUNT) {
        memcpy(data->sig[i], data->sig[0], 64);
        memcpy(data->msg[i], data->msg[0], 32);
      }
    }
}


void bench_recover_batch(void* arg) {
  size_t i, j, k;
  bench_recover_data *data = (bench_recover_data*)arg;
  unsigned char pubkeyc[33];


  for (i = 0; i < 200; i++) {
    size_t pubkeylen = 33;
    for (j = 0; j < RECOVER_AMOUNT; j++) {
      CHECK(secp256k1_ecdsa_signature_parse_compact(data->ctx, &data->sig_arr[j], data->sig[j]));
    }
    CHECK(secp256k1_ecdsa_recover_batch(data->ctx, data->scratch, data->keys_arr, data->pubkeys_n, data->sigs_ptrs, data->msgs_ptrs, RECOVER_AMOUNT));

    for (j = 0; j < RECOVER_AMOUNT; j++) {
      CHECK(data->pubkeys_n[j]>0);
      for (k = 0; k < data->pubkeys_n[j]; k++) {
        CHECK(secp256k1_ec_pubkey_serialize(data->ctx, pubkeyc, &pubkeylen, &data->keys_arr[(j*4)+k], SECP256K1_EC_COMPRESSED));
      }
    }
  }
}

void bench_recover_setup(void* arg) {
    int i;
    bench_recover_data *data = (bench_recover_data*)arg;

    for (i = 0; i < RECOVER_AMOUNT; i++) {
      data->sigs_ptrs[i] = &data->sig_arr[i];
      data->msgs_ptrs[i] = data->msg[i];
    }
    for (i = 0; i < 32; i++) {
        data->msg[0][i] = 1 + i;
    }
    for (i = 0; i < 64; i++) {
        data->sig[0][i] = 65 + i;
    }
}

int main(void) {
    bench_recover_data data;
    char name[64];

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
    data.scratch = secp256k1_scratch_space_create(data.ctx, 4 * RECOVER_AMOUNT * (104+152+16+BREATHING_OFFSET));

    run_benchmark("ecdsa_recover", bench_recover, bench_recover_setup, NULL, &data, 10, 20000);
    sprintf(name, "ecdsa_recover_batch: %d", RECOVER_AMOUNT);

    run_benchmark(name, bench_recover_batch, bench_recover_setup, NULL, &data, 10, RECOVER_AMOUNT*200);
    secp256k1_context_destroy(data.ctx);
    return 0;
}
