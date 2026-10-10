/***********************************************************************
 * Copyright (c) 2020 Elichai Turkel                                   *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_RECOVERY_FUZZ_H
#define SECP256K1_MODULE_RECOVERY_FUZZ_H

#include "../../../include/secp256k1_recovery.h"

/* Try parsing with all recids possible (0..=3), if succeeded serialize and compare. */
static int fuzz_recovery_parse_compare(const unsigned char *data64) {
    secp256k1_ecdsa_recoverable_signature sig;
    unsigned char serialized_sig[64];
    int recid;
    int success = 0;
    for (recid = 0; recid < 4; recid++) {
        if (fuzz_check_bool(secp256k1_ecdsa_recoverable_signature_parse_compact(fuzz_ctx, &sig, data64, recid))) {
            int new_recid;
            int new_ret = secp256k1_ecdsa_recoverable_signature_serialize_compact(fuzz_ctx, serialized_sig, &new_recid, &sig);
            CHECK(new_ret == 1);
            CHECK(new_recid == recid);
            CHECK(secp256k1_memcmp_var(serialized_sig, data64, sizeof(serialized_sig)) == 0);
            success = 1;
        }
    }
    return success;
}

static void fuzz_recovery(fuzz_data_provider *provider) {
    secp256k1_pubkey pubkey, recovered_pubkey;
    secp256k1_ecdsa_recoverable_signature sig;
    int recid;
    unsigned char serialized_sig[64];
    const unsigned char *seckey;
    const unsigned char *msg;

    seckey = fuzz_consume_seckey(provider);
    msg = fuzz_consume_bytes(provider, 32);
    if (!seckey || !msg) {
        return;
    }
    CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &pubkey, seckey) == 1);

    /* Compare recover(sign(seckey,msg)) == PubKey(seckey) */
    {
        CHECK(secp256k1_ecdsa_sign_recoverable(fuzz_ctx, &sig, msg, seckey, NULL, NULL) == 1);
        CHECK(secp256k1_ecdsa_recover(fuzz_ctx, &recovered_pubkey, &sig, msg) == 1);
        CHECK(secp256k1_memcmp_var(&recovered_pubkey, &pubkey, sizeof(pubkey)) == 0);
    }
    /* Compare parse(serialize(sig)) == sig */
    {
        secp256k1_ecdsa_recoverable_signature new_sig;
        CHECK(secp256k1_ecdsa_recoverable_signature_serialize_compact(fuzz_ctx, serialized_sig, &recid, &sig) == 1);
        CHECK(secp256k1_ecdsa_recoverable_signature_parse_compact(fuzz_ctx, &new_sig, serialized_sig, recid) == 1);
        CHECK(secp256k1_memcmp_var(&sig, &new_sig, sizeof(sig)) == 0);
    }
    /* Compare serialize(to_regular(sig)) == serialize(sig) (modulo the recid) */
    {
        unsigned char serialized_sig2[64];
        secp256k1_ecdsa_signature regular_sig;
        CHECK(secp256k1_ecdsa_recoverable_signature_convert(fuzz_ctx, &regular_sig, &sig) == 1);
        CHECK(secp256k1_ecdsa_signature_serialize_compact(fuzz_ctx, serialized_sig2, &regular_sig) == 1);
        CHECK(secp256k1_memcmp_var(serialized_sig, serialized_sig2, sizeof(serialized_sig)) == 0);
    }
    /* Try to parse+serialize the serialized sig with all recids, check that it succeeds at least once. */
    {
        int ret = fuzz_recovery_parse_compare(serialized_sig);
        CHECK(ret == 1);
    }
    /* Fuzz garbage through the parsing function */
    {
        const unsigned char *data64 = fuzz_consume_bytes(provider, 64);
        if (data64) {
            fuzz_recovery_parse_compare(data64);
        }
    }
    /* Sign with a nonce function that forces retries or fails */
    {
        fuzz_nonce_data nonce_data;
        int ret;
        if (fuzz_consume_nonce_data(provider, &nonce_data)) {
            ret = fuzz_check_bool(secp256k1_ecdsa_sign_recoverable(fuzz_ctx, &sig, msg, seckey, fuzz_nonce_function, &nonce_data));
            /* With a valid key, signing fails exactly when the nonce function does */
            CHECK(ret == !nonce_data.failed);
            if (ret) {
                CHECK(secp256k1_ecdsa_recover(fuzz_ctx, &recovered_pubkey, &sig, msg) == 1);
                CHECK(secp256k1_memcmp_var(&recovered_pubkey, &pubkey, sizeof(pubkey)) == 0);
            }
        }
    }
}

#endif /* SECP256K1_MODULE_RECOVERY_FUZZ_H */
