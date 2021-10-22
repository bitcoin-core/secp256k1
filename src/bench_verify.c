/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <stdio.h>
#include <string.h>

#include "../include/secp256k1.h"
#include "util.h"
#include "bench.h"

typedef struct {
    secp256k1_context *ctx;
    unsigned char msg[32];
    unsigned char key[32];
    unsigned char sig[72];
    size_t siglen;
    unsigned char pubkey[33];
    size_t pubkeylen;
} bench_verify_data;

static void bench_verify(void* arg, int iters) {
    int i;
    bench_verify_data* data = (bench_verify_data*)arg;

    for (i = 0; i < iters; i++) {
        secp256k1_pubkey pubkey;
        secp256k1_ecdsa_signature sig;
        data->sig[data->siglen - 1] ^= (i & 0xFF);
        data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
        data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
        CHECK(secp256k1_ec_pubkey_parse(data->ctx, &pubkey, data->pubkey, data->pubkeylen) == 1);
        CHECK(secp256k1_ecdsa_signature_parse_der(data->ctx, &sig, data->sig, data->siglen) == 1);
        CHECK(secp256k1_ecdsa_verify(data->ctx, &sig, data->msg, &pubkey) == (i == 0));
        data->sig[data->siglen - 1] ^= (i & 0xFF);
        data->sig[data->siglen - 2] ^= ((i >> 8) & 0xFF);
        data->sig[data->siglen - 3] ^= ((i >> 16) & 0xFF);
    }
}

int main(void) {
    int i;
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig;
    bench_verify_data data;

    int iters = get_iters(20000);

    data.ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    for (i = 0; i < 32; i++) {
        data.msg[i] = 1 + i;
    }
    for (i = 0; i < 32; i++) {
        data.key[i] = 33 + i;
    }
    data.siglen = 72;
    CHECK(secp256k1_ecdsa_sign(data.ctx, &sig, data.msg, data.key, NULL, NULL));
    CHECK(secp256k1_ecdsa_signature_serialize_der(data.ctx, data.sig, &data.siglen, &sig));
    CHECK(secp256k1_ec_pubkey_create(data.ctx, &pubkey, data.key));
    data.pubkeylen = 33;
    CHECK(secp256k1_ec_pubkey_serialize(data.ctx, data.pubkey, &data.pubkeylen, &pubkey, SECP256K1_EC_COMPRESSED) == 1);

    print_output_table_header_row();
    run_benchmark("ecdsa_verify", bench_verify, NULL, NULL, &data, 10, iters);

    secp256k1_context_destroy(data.ctx);
    return 0;
}
