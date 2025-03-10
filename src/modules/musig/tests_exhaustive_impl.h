/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_MUSIG_TESTS_EXHAUSTIVE_H
#define SECP256K1_MODULE_MUSIG_TESTS_EXHAUSTIVE_H

#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_musig.h"
#include "../../../include/secp256k1_schnorrsig.h"
#include "main_impl.h"

static void test_exhaustive_musig(const secp256k1_context *ctx) {
    int s1, s2;
    int skipped_iterations = 0;
    uint64_t nonce_counter = 0;
    /* TODO: improve this, maybe loop over all challenges like in the schnorr exhaustive test? */
    unsigned char message_to_sign[32] = "this_could_be_the_hash_of_a_msg";

    /* Exercise 2-of-2 musig, looping over all possible signing keys for both participants. Note that this
       test is not fully exhaustive, as other involved cryptographic elements (nonces, challenges etc.)
       are currently not exhausted, but either derived from a counter or constant. */
    for (s1 = 1; s1 < EXHAUSTIVE_TEST_ORDER; s1++) {
        for (s2 = 1; s2 < EXHAUSTIVE_TEST_ORDER; s2++) {
            /* TODO: move first participant's key generation to outer loop */
            secp256k1_scalar sc1, sc2;
            unsigned char seckey1[32], seckey2[32];
            secp256k1_keypair keypair1, keypair2;
            secp256k1_pubkey pubkey1, pubkey2;
            const secp256k1_pubkey *pubkeys_ptr[2];
            secp256k1_xonly_pubkey agg_pk;
            secp256k1_musig_keyagg_cache cache;
            secp256k1_musig_secnonce secnonce1, secnonce2;
            secp256k1_musig_pubnonce pubnonce1, pubnonce2;
            const secp256k1_musig_pubnonce *pubnonces[2];
            secp256k1_musig_aggnonce agg_pubnonce;
            secp256k1_musig_session session;
            secp256k1_musig_partial_sig partialsig1, partialsig2;
            const secp256k1_musig_partial_sig *partial_sigs_ptr[2];
            unsigned char agg_sig[64];
            int ret;

            /* Construct key pairs from exhaustive loop scalars s1, s2 */
            secp256k1_scalar_set_int(&sc1, s1);
            secp256k1_scalar_set_int(&sc2, s2);
            secp256k1_scalar_get_b32(seckey1, &sc1);
            secp256k1_scalar_get_b32(seckey2, &sc2);
            CHECK(secp256k1_keypair_create(ctx, &keypair1, seckey1));
            CHECK(secp256k1_keypair_create(ctx, &keypair2, seckey2));
            CHECK(secp256k1_keypair_pub(ctx, &pubkey1, &keypair1));
            CHECK(secp256k1_keypair_pub(ctx, &pubkey2, &keypair2));
            pubkeys_ptr[0] = &pubkey1;
            pubkeys_ptr[1] = &pubkey2;

            /* Aggregate public keys */
            if (!secp256k1_musig_pubkey_agg(ctx, &agg_pk, &cache, pubkeys_ptr, 2)) {
                /* can fail if aggregated pubkey is point at infinity */
                skipped_iterations++;
                continue;
            }

            /* Generate nonces (using the counter variant to keep it simple) and aggregate them */
            ret = 0;
            while (!ret) {
                /* can fail if one of the generated nonce scalars is zero, so try again in that case */
                ret = secp256k1_musig_nonce_gen_counter(ctx, &secnonce1, &pubnonce1,
                        nonce_counter++, &keypair1, NULL, NULL, NULL);
            }
            ret = 0;
            while (!ret) {
                ret = secp256k1_musig_nonce_gen_counter(ctx, &secnonce2, &pubnonce2,
                        nonce_counter++, &keypair2, NULL, NULL, NULL);
            }
            pubnonces[0] = &pubnonce1;
            pubnonces[1] = &pubnonce2;
            CHECK(secp256k1_musig_nonce_agg(ctx, &agg_pubnonce, pubnonces, 2));

            /* Start signing session */
            CHECK(secp256k1_musig_nonce_process(ctx, &session, &agg_pubnonce, message_to_sign, &cache));

            /* If the final nonce is the generator point, this means that possibly a reduction from an
               invalid final nonce (i.e. point of infinity) has happened and the aggregated signature
               verification would fail (see BIP327, section "Dealing with Infinity in Nonce Aggregation",
               and the `GetSessionValues` algorithm, at the condition `If is_infinite(R'):`), so skip
               the signing/verification part in this case.
               TODO: detect this directly in _musig_nonce_process and return 0 accordingly, in order to
                     avoid false positives (i.e. final nonce is the generator point without reduction),
                     leading to skips even if the aggregated signature verification would succeed
            */
            {
                secp256k1_musig_session_internal session_i;
                unsigned char ge_x[32];
                CHECK(secp256k1_musig_session_load(ctx, &session_i, &session));
                secp256k1_fe_get_b32(ge_x, &secp256k1_ge_const_g.x);
                if (secp256k1_memcmp_var(session_i.fin_nonce, ge_x, 32) == 0) {
                    skipped_iterations++;
                    continue;
                }
            }

            /* Create partial signatures and verify them */
            CHECK(secp256k1_musig_partial_sign(ctx, &partialsig1, &secnonce1, &keypair1, &cache, &session));
            CHECK(secp256k1_musig_partial_sign(ctx, &partialsig2, &secnonce2, &keypair2, &cache, &session));
            CHECK(secp256k1_musig_partial_sig_verify(ctx, &partialsig1, &pubnonce1, &pubkey1, &cache, &session));
            CHECK(secp256k1_musig_partial_sig_verify(ctx, &partialsig2, &pubnonce2, &pubkey2, &cache, &session));

            /* Aggregate signature and verify it */
            partial_sigs_ptr[0] = &partialsig1;
            partial_sigs_ptr[1] = &partialsig2;
            CHECK(secp256k1_musig_partial_sig_agg(ctx, agg_sig, &session, partial_sigs_ptr, 2));
            CHECK(secp256k1_schnorrsig_verify(ctx, agg_sig, message_to_sign, 32, &agg_pk));
        }
    }
    printf("musig exhaustive test, skipped iterations: %d/%d\n",
        skipped_iterations, (EXHAUSTIVE_TEST_ORDER-1)*(EXHAUSTIVE_TEST_ORDER-1));
}

#endif
