/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

/* Checks the documented guarantee that a context can be shared between threads.
 * Meant for a race detector like Helgrind or TSan, which reports writes to shared state. */

#include <pthread.h>
#include <stdlib.h>
#include <string.h>

#include "../include/secp256k1.h"
#include "../include/secp256k1_preallocated.h"
#include "util.h"

#ifdef ENABLE_MODULE_ECDH
# include "../include/secp256k1_ecdh.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "../include/secp256k1_recovery.h"
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
# include "../include/secp256k1_extrakeys.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
# include "../include/secp256k1_schnorrsig.h"
#endif

#ifdef ENABLE_MODULE_MUSIG
# include "../include/secp256k1_musig.h"
#endif

#ifdef ENABLE_MODULE_ELLSWIFT
# include "../include/secp256k1_ellswift.h"
#endif

#ifdef ENABLE_MODULE_SILENTPAYMENTS
# include "../include/secp256k1_silentpayments.h"
#endif

#define N_THREADS 4
#define N_ROUNDS 4

/* Deterministic inputs keep failures reproducible. */
static void derive(unsigned char *out32, const char *label, int round, int index) {
    static const unsigned char tag[] = "secp256k1 thread_tests";
    unsigned char msg[64];
    size_t len = strlen(label);

    CHECK(len + 2 <= sizeof(msg));
    memcpy(msg, label, len);
    msg[len] = (unsigned char)round;
    msg[len + 1] = (unsigned char)index;
    CHECK(secp256k1_tagged_sha256(secp256k1_context_static, out32, tag, sizeof(tag) - 1, msg, len + 2));
}

/* Verification uses secp256k1_context_static, which callers also share between threads. */
static void run_ecdsa(const secp256k1_context *ctx, int round) {
    unsigned char seckey[32], msg[32], der[72];
    size_t der_len = sizeof(der);
    secp256k1_pubkey pubkey;
    secp256k1_ecdsa_signature sig, parsed;

    derive(seckey, "ecdsa seckey", round, 0);
    derive(msg, "ecdsa msg", round, 0);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey));
    CHECK(secp256k1_ecdsa_sign(ctx, &sig, msg, seckey, NULL, NULL));
    CHECK(secp256k1_ecdsa_signature_serialize_der(secp256k1_context_static, der, &der_len, &sig));
    CHECK(secp256k1_ecdsa_signature_parse_der(secp256k1_context_static, &parsed, der, der_len));
    CHECK(secp256k1_ecdsa_verify(secp256k1_context_static, &parsed, msg, &pubkey));
}

static void run_pubkeys(const secp256k1_context *ctx, int round) {
    unsigned char seckey_a[32], seckey_b[32], serialized[33];
    size_t serialized_len = sizeof(serialized);
    secp256k1_pubkey pubkey_a, pubkey_b, parsed, combined, tweaked, expected;
    const secp256k1_pubkey *pubkey_ptrs[2];

    derive(seckey_a, "pubkeys seckey", round, 0);
    derive(seckey_b, "pubkeys seckey", round, 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey_a, seckey_a));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey_b, seckey_b));
    CHECK(secp256k1_ec_pubkey_serialize(secp256k1_context_static, serialized, &serialized_len, &pubkey_a, SECP256K1_EC_COMPRESSED));
    CHECK(secp256k1_ec_pubkey_parse(secp256k1_context_static, &parsed, serialized, serialized_len));
    CHECK(secp256k1_ec_pubkey_cmp(secp256k1_context_static, &parsed, &pubkey_a) == 0);

    /* Compute (a + b)*G three ways. */
    pubkey_ptrs[0] = &pubkey_a;
    pubkey_ptrs[1] = &pubkey_b;
    CHECK(secp256k1_ec_pubkey_combine(secp256k1_context_static, &combined, pubkey_ptrs, 2));
    tweaked = pubkey_a;
    CHECK(secp256k1_ec_pubkey_tweak_add(secp256k1_context_static, &tweaked, seckey_b));
    CHECK(secp256k1_ec_seckey_tweak_add(ctx, seckey_a, seckey_b));
    CHECK(secp256k1_ec_pubkey_create(ctx, &expected, seckey_a));
    CHECK(secp256k1_ec_pubkey_cmp(secp256k1_context_static, &combined, &expected) == 0);
    CHECK(secp256k1_ec_pubkey_cmp(secp256k1_context_static, &tweaked, &expected) == 0);

    CHECK(secp256k1_ec_pubkey_sort(secp256k1_context_static, pubkey_ptrs, 2));
    CHECK(secp256k1_ec_pubkey_cmp(secp256k1_context_static, pubkey_ptrs[0], pubkey_ptrs[1]) < 0);
}

static void run_negate_mul(const secp256k1_context *ctx, int round) {
    unsigned char seckey[32], tweak[32];
    secp256k1_pubkey pubkey, expected;

    derive(seckey, "negate_mul seckey", round, 0);
    derive(tweak, "negate_mul tweak", round, 0);
    CHECK(secp256k1_ec_seckey_verify(ctx, seckey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey));

    /* Compute -(tweak * seckey)*G from both the secret and the public key. */
    CHECK(secp256k1_ec_seckey_tweak_mul(ctx, seckey, tweak));
    CHECK(secp256k1_ec_seckey_negate(ctx, seckey));
    CHECK(secp256k1_ec_pubkey_tweak_mul(secp256k1_context_static, &pubkey, tweak));
    CHECK(secp256k1_ec_pubkey_negate(secp256k1_context_static, &pubkey));
    CHECK(secp256k1_ec_pubkey_create(ctx, &expected, seckey));
    CHECK(secp256k1_ec_pubkey_cmp(secp256k1_context_static, &pubkey, &expected) == 0);
}

#ifdef ENABLE_MODULE_ECDH
static void run_ecdh(const secp256k1_context *ctx, int round) {
    unsigned char seckey_a[32], seckey_b[32], secret_a[32], secret_b[32];
    secp256k1_pubkey pubkey_a, pubkey_b;

    derive(seckey_a, "ecdh seckey", round, 0);
    derive(seckey_b, "ecdh seckey", round, 1);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey_a, seckey_a));
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey_b, seckey_b));
    CHECK(secp256k1_ecdh(ctx, secret_a, &pubkey_b, seckey_a, NULL, NULL));
    CHECK(secp256k1_ecdh(ctx, secret_b, &pubkey_a, seckey_b, NULL, NULL));
    CHECK(memcmp(secret_a, secret_b, sizeof(secret_a)) == 0);
}
#endif

#ifdef ENABLE_MODULE_RECOVERY
static void run_recovery(const secp256k1_context *ctx, int round) {
    unsigned char seckey[32], msg[32];
    secp256k1_pubkey pubkey, recovered;
    secp256k1_ecdsa_recoverable_signature sig;

    derive(seckey, "recovery seckey", round, 0);
    derive(msg, "recovery msg", round, 0);
    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey));
    CHECK(secp256k1_ecdsa_sign_recoverable(ctx, &sig, msg, seckey, NULL, NULL));
    CHECK(secp256k1_ecdsa_recover(secp256k1_context_static, &recovered, &sig, msg));
    CHECK(secp256k1_ec_pubkey_cmp(secp256k1_context_static, &pubkey, &recovered) == 0);
}
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
static void run_extrakeys(const secp256k1_context *ctx, int round) {
    unsigned char seckey[32], tweak[32], output32[32];
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey internal, output;
    secp256k1_pubkey tweaked, expected;
    int parity;

    derive(seckey, "extrakeys seckey", round, 0);
    derive(tweak, "extrakeys tweak", round, 0);
    CHECK(secp256k1_keypair_create(ctx, &keypair, seckey));
    CHECK(secp256k1_keypair_xonly_pub(ctx, &internal, NULL, &keypair));
    CHECK(secp256k1_keypair_xonly_tweak_add(ctx, &keypair, tweak));
    CHECK(secp256k1_keypair_xonly_pub(ctx, &output, &parity, &keypair));
    CHECK(secp256k1_xonly_pubkey_serialize(ctx, output32, &output));
    CHECK(secp256k1_xonly_pubkey_tweak_add_check(secp256k1_context_static, output32, parity, &internal, tweak));
    CHECK(secp256k1_xonly_pubkey_tweak_add(secp256k1_context_static, &tweaked, &internal, tweak));
    CHECK(secp256k1_keypair_pub(ctx, &expected, &keypair));
    CHECK(secp256k1_ec_pubkey_cmp(secp256k1_context_static, &tweaked, &expected) == 0);
}
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
static void run_schnorrsig(const secp256k1_context *ctx, int round) {
    unsigned char seckey[32], msg[32], aux_rand[32], sig[64], sig_custom[64];
    secp256k1_schnorrsig_extraparams extraparams = SECP256K1_SCHNORRSIG_EXTRAPARAMS_INIT;
    secp256k1_keypair keypair;
    secp256k1_xonly_pubkey pubkey;

    derive(seckey, "schnorrsig seckey", round, 0);
    derive(msg, "schnorrsig msg", round, 0);
    derive(aux_rand, "schnorrsig aux_rand", round, 0);
    CHECK(secp256k1_keypair_create(ctx, &keypair, seckey));
    CHECK(secp256k1_keypair_xonly_pub(ctx, &pubkey, NULL, &keypair));
    CHECK(secp256k1_schnorrsig_sign32(ctx, sig, msg, &keypair, aux_rand));
    CHECK(secp256k1_schnorrsig_verify(secp256k1_context_static, sig, msg, sizeof(msg), &pubkey));

    /* With these extraparams, sign_custom is documented to match sign32. */
    extraparams.ndata = aux_rand;
    CHECK(secp256k1_schnorrsig_sign_custom(ctx, sig_custom, msg, sizeof(msg), &keypair, &extraparams));
    CHECK(memcmp(sig, sig_custom, sizeof(sig)) == 0);
}
#endif

#ifdef ENABLE_MODULE_MUSIG
#define N_MUSIG_SIGNERS 2

static void run_musig(const secp256k1_context *ctx, int round) {
    unsigned char seckey[32], session_secrand[32], msg[32], tweak[32], sig[64];
    secp256k1_keypair keypairs[N_MUSIG_SIGNERS];
    secp256k1_pubkey pubkeys[N_MUSIG_SIGNERS];
    const secp256k1_pubkey *pubkey_ptrs[N_MUSIG_SIGNERS];
    secp256k1_musig_secnonce secnonces[N_MUSIG_SIGNERS];
    secp256k1_musig_pubnonce pubnonces[N_MUSIG_SIGNERS];
    const secp256k1_musig_pubnonce *pubnonce_ptrs[N_MUSIG_SIGNERS];
    secp256k1_musig_partial_sig partial_sigs[N_MUSIG_SIGNERS];
    const secp256k1_musig_partial_sig *partial_sig_ptrs[N_MUSIG_SIGNERS];
    secp256k1_musig_keyagg_cache keyagg_cache;
    secp256k1_musig_aggnonce aggnonce;
    secp256k1_musig_session session;
    secp256k1_pubkey output_pk;
    secp256k1_xonly_pubkey agg_pk;
    int i;

    derive(msg, "musig msg", round, 0);
    for (i = 0; i < N_MUSIG_SIGNERS; i++) {
        derive(seckey, "musig seckey", round, i);
        derive(session_secrand, "musig session_secrand", round, i);
        CHECK(secp256k1_keypair_create(ctx, &keypairs[i], seckey));
        CHECK(secp256k1_keypair_pub(ctx, &pubkeys[i], &keypairs[i]));
        /* Cover both nonce generation functions. */
        if (i == 0) {
            CHECK(secp256k1_musig_nonce_gen(ctx, &secnonces[i], &pubnonces[i], session_secrand, seckey, &pubkeys[i], msg, NULL, NULL));
        } else {
            CHECK(secp256k1_musig_nonce_gen_counter(ctx, &secnonces[i], &pubnonces[i], (uint64_t)round, &keypairs[i], msg, NULL, NULL));
        }
        pubkey_ptrs[i] = &pubkeys[i];
        pubnonce_ptrs[i] = &pubnonces[i];
    }
    CHECK(secp256k1_musig_pubkey_agg(ctx, NULL, &keyagg_cache, pubkey_ptrs, N_MUSIG_SIGNERS));
    derive(tweak, "musig tweak", round, 0);
    CHECK(secp256k1_musig_pubkey_ec_tweak_add(ctx, NULL, &keyagg_cache, tweak));
    derive(tweak, "musig tweak", round, 1);
    CHECK(secp256k1_musig_pubkey_xonly_tweak_add(ctx, &output_pk, &keyagg_cache, tweak));
    CHECK(secp256k1_xonly_pubkey_from_pubkey(ctx, &agg_pk, NULL, &output_pk));
    CHECK(secp256k1_musig_nonce_agg(ctx, &aggnonce, pubnonce_ptrs, N_MUSIG_SIGNERS));
    CHECK(secp256k1_musig_nonce_process(ctx, &session, &aggnonce, msg, &keyagg_cache));
    for (i = 0; i < N_MUSIG_SIGNERS; i++) {
        CHECK(secp256k1_musig_partial_sign(ctx, &partial_sigs[i], &secnonces[i], &keypairs[i], &keyagg_cache, &session));
        CHECK(secp256k1_musig_partial_sig_verify(ctx, &partial_sigs[i], &pubnonces[i], &pubkeys[i], &keyagg_cache, &session));
        partial_sig_ptrs[i] = &partial_sigs[i];
    }
    CHECK(secp256k1_musig_partial_sig_agg(ctx, sig, &session, partial_sig_ptrs, N_MUSIG_SIGNERS));
    CHECK(secp256k1_schnorrsig_verify(secp256k1_context_static, sig, msg, sizeof(msg), &agg_pk));
}
#endif

#ifdef ENABLE_MODULE_ELLSWIFT
static void run_ellswift(const secp256k1_context *ctx, int round) {
    unsigned char seckey_a[32], seckey_b[32], auxrnd[32], ell_a[64], ell_b[64], ell_encoded[64], secret_a[32], secret_b[32];
    secp256k1_pubkey pubkey, decoded;

    derive(seckey_a, "ellswift seckey", round, 0);
    derive(seckey_b, "ellswift seckey", round, 1);
    derive(auxrnd, "ellswift auxrnd", round, 0);
    CHECK(secp256k1_ellswift_create(ctx, ell_a, seckey_a, auxrnd));
    CHECK(secp256k1_ellswift_create(ctx, ell_b, seckey_b, auxrnd));
    CHECK(secp256k1_ellswift_xdh(ctx, secret_a, ell_a, ell_b, seckey_a, 0, secp256k1_ellswift_xdh_hash_function_bip324, NULL));
    CHECK(secp256k1_ellswift_xdh(ctx, secret_b, ell_a, ell_b, seckey_b, 1, secp256k1_ellswift_xdh_hash_function_bip324, NULL));
    CHECK(memcmp(secret_a, secret_b, sizeof(secret_a)) == 0);

    CHECK(secp256k1_ec_pubkey_create(ctx, &pubkey, seckey_a));
    CHECK(secp256k1_ellswift_decode(secp256k1_context_static, &decoded, ell_a));
    CHECK(secp256k1_ec_pubkey_cmp(secp256k1_context_static, &decoded, &pubkey) == 0);
    CHECK(secp256k1_ellswift_encode(ctx, ell_encoded, &pubkey, auxrnd));
    CHECK(secp256k1_ellswift_decode(secp256k1_context_static, &decoded, ell_encoded));
    CHECK(secp256k1_ec_pubkey_cmp(secp256k1_context_static, &decoded, &pubkey) == 0);
}
#endif

#ifdef ENABLE_MODULE_SILENTPAYMENTS
struct label_cache_entry {
    unsigned char label33[33];
    unsigned char tweak32[32];
};

static const unsigned char *lookup_label(const unsigned char *label33, const void *label_context) {
    const struct label_cache_entry *entry = (const struct label_cache_entry *)label_context;
    return memcmp(label33, entry->label33, sizeof(entry->label33)) == 0 ? entry->tweak32 : NULL;
}

static void run_silentpayments(const secp256k1_context *ctx, int round) {
    unsigned char sender_seckey[32], scan_key[32], spend_key[32], outpoint[36];
    struct label_cache_entry label_cache;
    secp256k1_silentpayments_label label;
    secp256k1_pubkey spend_pubkey;
    secp256k1_keypair sender_keypair;
    const secp256k1_keypair *sender_keypair_ptrs[1];
    secp256k1_xonly_pubkey input;
    const secp256k1_xonly_pubkey *input_ptrs[1];
    secp256k1_silentpayments_recipient recipient;
    const secp256k1_silentpayments_recipient *recipient_ptrs[1];
    secp256k1_xonly_pubkey output;
    secp256k1_xonly_pubkey *output_ptrs[1];
    const secp256k1_xonly_pubkey *tx_output_ptrs[1];
    secp256k1_silentpayments_prevouts_summary prevouts_summary;
    secp256k1_silentpayments_found_output found;
    secp256k1_silentpayments_found_output *found_ptrs[1];
    uint32_t n_found;

    derive(sender_seckey, "silentpayments sender_seckey", round, 0);
    derive(scan_key, "silentpayments scan_key", round, 0);
    derive(spend_key, "silentpayments spend_key", round, 0);
    derive(outpoint, "silentpayments outpoint", round, 0);
    memset(outpoint + 32, 0, 4);

    CHECK(secp256k1_keypair_create(ctx, &sender_keypair, sender_seckey));
    CHECK(secp256k1_keypair_xonly_pub(ctx, &input, NULL, &sender_keypair));
    CHECK(secp256k1_ec_pubkey_create(ctx, &recipient.scan_pubkey, scan_key));
    CHECK(secp256k1_ec_pubkey_create(ctx, &spend_pubkey, spend_key));
    CHECK(secp256k1_silentpayments_recipient_label_create(ctx, &label, label_cache.tweak32, scan_key, 1));
    CHECK(secp256k1_silentpayments_recipient_label_serialize(ctx, label_cache.label33, &label));
    CHECK(secp256k1_silentpayments_recipient_create_labeled_spend_pubkey(ctx, &recipient.spend_pubkey, &spend_pubkey, &label));
    recipient.index = 0;
    sender_keypair_ptrs[0] = &sender_keypair;
    recipient_ptrs[0] = &recipient;
    output_ptrs[0] = &output;
    CHECK(secp256k1_silentpayments_sender_create_outputs(ctx, output_ptrs, recipient_ptrs, 1, outpoint, sender_keypair_ptrs, 1, NULL, 0));

    input_ptrs[0] = &input;
    tx_output_ptrs[0] = &output;
    found_ptrs[0] = &found;
    CHECK(secp256k1_silentpayments_recipient_prevouts_summary_create(ctx, &prevouts_summary, outpoint, input_ptrs, 1, NULL, 0));
    CHECK(secp256k1_silentpayments_recipient_scan_outputs(ctx, found_ptrs, &n_found, tx_output_ptrs, 1, scan_key, &prevouts_summary, &spend_pubkey, lookup_label, &label_cache));
    CHECK(n_found == 1);
    CHECK(found.found_with_label);
    CHECK(secp256k1_xonly_pubkey_cmp(ctx, &found.output, &output) == 0);
}
#endif

struct worker_args {
    const secp256k1_context *ctx;
    int first_round;
};

static void *worker(void *data) {
    const struct worker_args *args = (const struct worker_args *)data;
    void *prealloc;
    int round;

    /* Cloning reads the whole shared context. */
    secp256k1_context_destroy(secp256k1_context_clone(args->ctx));
    prealloc = malloc(secp256k1_context_preallocated_clone_size(args->ctx));
    CHECK(prealloc != NULL);
    secp256k1_context_preallocated_destroy(secp256k1_context_preallocated_clone(args->ctx, prealloc));
    free(prealloc);
    for (round = args->first_round; round < args->first_round + N_ROUNDS; round++) {
        run_ecdsa(args->ctx, round);
        run_pubkeys(args->ctx, round);
        run_negate_mul(args->ctx, round);
#ifdef ENABLE_MODULE_ECDH
        run_ecdh(args->ctx, round);
#endif
#ifdef ENABLE_MODULE_RECOVERY
        run_recovery(args->ctx, round);
#endif
#ifdef ENABLE_MODULE_EXTRAKEYS
        run_extrakeys(args->ctx, round);
#endif
#ifdef ENABLE_MODULE_SCHNORRSIG
        run_schnorrsig(args->ctx, round);
#endif
#ifdef ENABLE_MODULE_MUSIG
        run_musig(args->ctx, round);
#endif
#ifdef ENABLE_MODULE_ELLSWIFT
        run_ellswift(args->ctx, round);
#endif
#ifdef ENABLE_MODULE_SILENTPAYMENTS
        run_silentpayments(args->ctx, round);
#endif
    }
    return NULL;
}

int main(void) {
    pthread_t threads[N_THREADS];
    struct worker_args args[N_THREADS];
    unsigned char seed[32];
    secp256k1_context *ctx;
    int i;

    ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    /* Randomization needs exclusive access, so do it before sharing the context. */
    derive(seed, "randomize", 0, 0);
    CHECK(secp256k1_context_randomize(ctx, seed));

    for (i = 0; i < N_THREADS; i++) {
        args[i].ctx = ctx;
        args[i].first_round = i * N_ROUNDS;
        CHECK(pthread_create(&threads[i], NULL, worker, &args[i]) == 0);
    }
    for (i = 0; i < N_THREADS; i++) {
        CHECK(pthread_join(threads[i], NULL) == 0);
    }

    secp256k1_context_destroy(ctx);
    return EXIT_SUCCESS;
}
