/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_FUZZ_H
#define SECP256K1_MODULE_MUSIG_FUZZ_H

#include "../../../include/secp256k1_musig.h"
#include "../../../include/secp256k1_schnorrsig.h"

/* One two-signer session per input: each secnonce signs once. */
static void fuzz_musig(fuzz_data_provider *provider) {
    secp256k1_keypair keypair[2];
    secp256k1_pubkey pk[2];
    const secp256k1_pubkey *pk_ptr[2];
    secp256k1_xonly_pubkey agg_pk, agg_pk_reversed;
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_secnonce secnonce[2];
    secp256k1_musig_pubnonce pubnonce[2];
    const secp256k1_musig_pubnonce *pubnonce_ptr[2];
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_session session;
    secp256k1_musig_partial_sig partial_sig[2];
    const secp256k1_musig_partial_sig *partial_sig_ptr[2];
    unsigned char session_secrand[2][32];
    unsigned char sig[64];
    const unsigned char *seckey[2], *secrand[2], *msg32, *flip;
    int i;

    seckey[0] = fuzz_consume_seckey(provider);
    seckey[1] = fuzz_consume_seckey(provider);
    msg32 = fuzz_consume_bytes(provider, 32);
    secrand[0] = fuzz_consume_bytes(provider, 32);
    secrand[1] = fuzz_consume_bytes(provider, 32);
    if (!seckey[0] || !seckey[1] || !msg32 || !secrand[0] || !secrand[1]) {
        return;
    }
    for (i = 0; i < 2; i++) {
        CHECK(secp256k1_keypair_create(fuzz_ctx, &keypair[i], seckey[i]) == 1);
        CHECK(secp256k1_keypair_pub(fuzz_ctx, &pk[i], &keypair[i]) == 1);
    }

    /* Once sorted, the order of the keys does not change the aggregate */
    pk_ptr[0] = &pk[1]; pk_ptr[1] = &pk[0];
    CHECK(secp256k1_ec_pubkey_sort(fuzz_ctx, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(fuzz_ctx, &agg_pk_reversed, NULL, pk_ptr, 2) == 1);
    pk_ptr[0] = &pk[0]; pk_ptr[1] = &pk[1];
    CHECK(secp256k1_ec_pubkey_sort(fuzz_ctx, pk_ptr, 2) == 1);
    CHECK(secp256k1_musig_pubkey_agg(fuzz_ctx, &agg_pk, &keyagg_cache, pk_ptr, 2) == 1);
    CHECK(secp256k1_xonly_pubkey_cmp(fuzz_ctx, &agg_pk, &agg_pk_reversed) == 0);

    for (i = 0; i < 2; i++) {
        static const unsigned char zeros32[32] = {0};
        int ret;
        memcpy(session_secrand[i], secrand[i], 32);
        ret = secp256k1_musig_nonce_gen(fuzz_ctx, &secnonce[i], &pubnonce[i], session_secrand[i], seckey[i], &pk[i], msg32, NULL, NULL);
        /* The API does not document the result for an all-zero session_secrand32 */
        if (secp256k1_memcmp_var(secrand[i], zeros32, 32) == 0) {
            return;
        }
        CHECK(ret == 1);
        pubnonce_ptr[i] = &pubnonce[i];
    }
    CHECK(secp256k1_musig_nonce_agg(fuzz_ctx, &aggnonce, pubnonce_ptr, 2) == 1);
    CHECK(secp256k1_musig_nonce_process(fuzz_ctx, &session, &aggnonce, msg32, &keyagg_cache) == 1);
    for (i = 0; i < 2; i++) {
        CHECK(secp256k1_musig_partial_sign(fuzz_ctx, &partial_sig[i], &secnonce[i], &keypair[i], &keyagg_cache, &session) == 1);
        CHECK(secp256k1_musig_partial_sig_verify(fuzz_ctx, &partial_sig[i], &pubnonce[i], &pk[i], &keyagg_cache, &session) == 1);
        partial_sig_ptr[i] = &partial_sig[i];
    }
    CHECK(secp256k1_musig_partial_sig_agg(fuzz_ctx, sig, &session, partial_sig_ptr, 2) == 1);
    CHECK(secp256k1_schnorrsig_verify(fuzz_ctx, sig, msg32, 32, &agg_pk) == 1);

    /* A tampered partial signature does not verify */
    flip = fuzz_consume_bytes(provider, 2);
    if (flip && flip[1] != 0) {
        secp256k1_musig_partial_sig tampered;
        unsigned char ser[32];
        CHECK(secp256k1_musig_partial_sig_serialize(fuzz_ctx, ser, &partial_sig[0]) == 1);
        ser[flip[0] % 32] ^= flip[1];
        if (secp256k1_musig_partial_sig_parse(fuzz_ctx, &tampered, ser)) {
            CHECK(secp256k1_musig_partial_sig_verify(fuzz_ctx, &tampered, &pubnonce[0], &pk[0], &keyagg_cache, &session) == 0);
        }
    }
}

#endif /* SECP256K1_MODULE_MUSIG_FUZZ_H */
