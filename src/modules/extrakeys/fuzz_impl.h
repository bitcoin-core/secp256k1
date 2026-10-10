/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_EXTRAKEYS_FUZZ_H
#define SECP256K1_MODULE_EXTRAKEYS_FUZZ_H

#include "../../../include/secp256k1_extrakeys.h"

static void fuzz_extrakeys(fuzz_data_provider *provider) {
    /* keypair_pub and keypair_xonly_pub agree with pubkey_create and xonly_pubkey_from_pubkey */
    {
        const unsigned char *seckey = fuzz_consume_seckey(provider);
        const unsigned char *tweak = fuzz_consume_bytes(provider, 32);
        if (seckey && tweak) {
            secp256k1_keypair keypair;
            secp256k1_pubkey pubkey, kp_pubkey, tweaked, kp_tweaked;
            secp256k1_xonly_pubkey xonly, kp_xonly, parsed;
            unsigned char ser[32];
            int parity, kp_parity, ret;

            CHECK(secp256k1_keypair_create(fuzz_ctx, &keypair, seckey) == 1);
            CHECK(secp256k1_ec_pubkey_create(fuzz_ctx, &pubkey, seckey) == 1);
            CHECK(secp256k1_keypair_pub(fuzz_ctx, &kp_pubkey, &keypair) == 1);
            CHECK(secp256k1_memcmp_var(&pubkey, &kp_pubkey, sizeof(pubkey)) == 0);
            CHECK(secp256k1_xonly_pubkey_from_pubkey(fuzz_ctx, &xonly, &parity, &pubkey) == 1);
            CHECK(secp256k1_keypair_xonly_pub(fuzz_ctx, &kp_xonly, &kp_parity, &keypair) == 1);
            CHECK(secp256k1_xonly_pubkey_cmp(fuzz_ctx, &xonly, &kp_xonly) == 0);
            CHECK(parity == kp_parity);

            /* Serialize/parse round trip */
            CHECK(secp256k1_xonly_pubkey_serialize(fuzz_ctx, ser, &xonly) == 1);
            CHECK(secp256k1_xonly_pubkey_parse(fuzz_ctx, &parsed, ser) == 1);
            CHECK(secp256k1_xonly_pubkey_cmp(fuzz_ctx, &xonly, &parsed) == 0);

            /* Both tweaks fail together: on a tweak >= n, or one that cancels the even-y secret key */
            ret = fuzz_check_bool(secp256k1_xonly_pubkey_tweak_add(fuzz_ctx, &tweaked, &xonly, tweak));
            CHECK(secp256k1_keypair_xonly_tweak_add(fuzz_ctx, &keypair, tweak) == ret);
            if (!ret) {
                static const unsigned char zeros32[32] = {0};
                unsigned char cancelling[32];
                memcpy(cancelling, seckey, sizeof(cancelling));
                if (!parity) {
                    CHECK(secp256k1_ec_seckey_negate(fuzz_ctx, cancelling) == 1);
                }
                CHECK((!fuzz_check_bool(secp256k1_ec_seckey_verify(fuzz_ctx, tweak)) && secp256k1_memcmp_var(tweak, zeros32, 32) != 0)
                      || secp256k1_memcmp_var(tweak, cancelling, 32) == 0);
            } else {
                CHECK(secp256k1_keypair_pub(fuzz_ctx, &kp_tweaked, &keypair) == 1);
                CHECK(secp256k1_memcmp_var(&tweaked, &kp_tweaked, sizeof(tweaked)) == 0);
                CHECK(secp256k1_xonly_pubkey_from_pubkey(fuzz_ctx, &kp_xonly, &kp_parity, &tweaked) == 1);
                CHECK(secp256k1_xonly_pubkey_serialize(fuzz_ctx, ser, &kp_xonly) == 1);
                CHECK(secp256k1_xonly_pubkey_tweak_add_check(fuzz_ctx, ser, kp_parity, &xonly, tweak) == 1);
                CHECK(secp256k1_xonly_pubkey_tweak_add_check(fuzz_ctx, ser, !kp_parity, &xonly, tweak) == 0);
            }
        }
    }
    /* Garbage through xonly_pubkey_parse: a successful parse round-trips */
    {
        const unsigned char *input32 = fuzz_consume_bytes(provider, 32);
        if (input32) {
            secp256k1_xonly_pubkey xonly;
            unsigned char ser[32];
            if (fuzz_check_bool(secp256k1_xonly_pubkey_parse(fuzz_ctx, &xonly, input32))) {
                CHECK(secp256k1_xonly_pubkey_serialize(fuzz_ctx, ser, &xonly) == 1);
                CHECK(secp256k1_memcmp_var(ser, input32, sizeof(ser)) == 0);
            }
        }
    }
}

#endif /* SECP256K1_MODULE_EXTRAKEYS_FUZZ_H */
