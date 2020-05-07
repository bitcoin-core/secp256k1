/**********************************************************************
 * Copyright (c) 2020 Elichai Turkel                                  *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/
#ifndef SECP256K1_MODULE_RECOVERY_FUZZ_IMPL_H
#define SECP256K1_MODULE_RECOVERY_FUZZ_IMPL_H

#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "include/secp256k1_recovery.h"
#include "src/util.h"
#include "src/fuzz/fuzz.h"

static secp256k1_context* ctx = NULL;

void initialize() {
    ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
    CHECK(ctx != NULL);
}

/* Try parsing with all recids possible (0..=3), if succeeded serialize and compare. */
static int parse_compare_recoverable_signature(const unsigned char* data64) {
    secp256k1_ecdsa_recoverable_signature sig;
    unsigned char serialized_sig[64];
    int recid;
    int success = 0;
    for (recid = 0; recid < 4; recid++) {
        int ret = secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &sig, data64, recid);
        CHECK(ret == 0 || ret == 1);
        if (ret) {
            int new_recid;
            int new_ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, serialized_sig, &new_recid, &sig);
            CHECK(new_ret == 1);
            CHECK(new_recid == recid);
            CHECK(memcmp(serialized_sig, data64, sizeof(serialized_sig)) == 0);
            success = 1;
        }
    }
    return success;
}


void test_one_input(fuzzed_data_provider* provider) {
    secp256k1_pubkey pubkey, recovered_pubkey;
    secp256k1_ecdsa_recoverable_signature sig;
    int recid;
    unsigned char serialized_sig[64];
    const unsigned char* seckey;
    const unsigned char* msg;

    seckey = consume_seckey(provider);
    msg = consume_bytes(provider, 32);
    if (!seckey || !msg) {
        return;
    }
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey) == 1);

    /* Compare recover(sign(seckey,msg)) == PubKey(seckey) */
    {
        CHECK(secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg, seckey, NULL, NULL) == 1);
        CHECK(secp256k1_ecdsa_recover(ctx, &recovered_pubkey, &sig, msg) == 1);
        CHECK(memcmp(&recovered_pubkey, &pubkey, sizeof(pubkey)) == 0);
    }
    /* Compare parse(serialize(sig)) == sig */
    {
        secp256k1_ecdsa_recoverable_signature new_sig;
        CHECK(secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx, serialized_sig, &recid, &sig) == 1);
        CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &new_sig, serialized_sig, recid) == 1);
        CHECK(memcmp(&sig, &new_sig, sizeof(sig)) == 0);

    }
    /* Compare serialize(to_regular(sig)) == serialize(sig) (modulo the recid) */
    {
        unsigned char serialized_sig2[64];
        secp256k1_ecdsa_signature regular_sig;
        CHECK(secp256k1_ecdsa_recoverable_signature_convert(ctx, &regular_sig, &sig) == 1);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(ctx, serialized_sig2, &regular_sig) == 1);
        CHECK(memcmp(serialized_sig, serialized_sig2, sizeof(serialized_sig)) == 0);
    }
    /* Try to parse+serialzie the serialized sig with all recids, check that it succeeds at least once. */
    {
        int ret = parse_compare_recoverable_signature(serialized_sig);
        CHECK(ret == 1);
    }
    /* Fuzz Garbage through the parsing function */
    {
        const unsigned char* data64 = consume_bytes(provider, 64);
        if (data64) {
            parse_compare_recoverable_signature(data64);
        }
    }
}

#endif /* SECP256K1_MODULE_RECOVERY_FUZZ_IMPL_H */
