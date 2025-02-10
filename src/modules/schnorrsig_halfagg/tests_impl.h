#ifndef SECP256K1_MODULE_SCHNORRSIG_HALFAGG_TESTS_H
#define SECP256K1_MODULE_SCHNORRSIG_HALFAGG_TESTS_H

#include "../../../include/secp256k1_schnorrsig_halfagg.h"

#define N_MAX 50

/* We test that the hash initialized by secp256k1_schnorrsig_sha256_tagged_aggregate
 * has the expected state. */
void test_schnorrsig_sha256_tagged_aggregate(void) {
    unsigned char tag[] = {'H', 'a', 'l', 'f', 'A', 'g', 'g', '/', 'r', 'a', 'n', 'd', 'o', 'm', 'i', 'z', 'e', 'r'};
    secp256k1_sha256 sha;
    secp256k1_sha256 sha_optimized;

    secp256k1_sha256_initialize_tagged(&sha, (unsigned char *) tag, sizeof(tag));
    secp256k1_schnorrsig_sha256_tagged_aggregation(&sha_optimized);
    test_sha256_eq(&sha, &sha_optimized);
}

/* Create n many x-only pubkeys and sigs for random messages */
void test_schnorrsig_aggregate_input_helper(secp256k1_xonly_pubkey *pubkeys, unsigned char *msgs32, unsigned char *sigs64, size_t n) {
    size_t i;
    for (i = 0; i < n; ++i) {
        unsigned char sk[32];
        secp256k1_keypair keypair;
        testrand256(sk);
        testrand256(&msgs32[i*32]);

        CHECK(secp256k1_keypair_create(CTX, &keypair, sk));
        CHECK(secp256k1_keypair_xonly_pub(CTX, &pubkeys[i], NULL, &keypair));
        CHECK(secp256k1_schnorrsig_sign(CTX, &sigs64[i*64], &msgs32[i*32], &keypair, NULL));
    }
}

/* In this test we create a bunch of Schnorr signatures,
 * aggregate some of them in one shot, and then
 * aggregate the others incrementally to the already aggregated ones.
 * The aggregate signature should verify after both steps. */
void test_schnorrsig_aggregate(void) {
    secp256k1_xonly_pubkey pubkeys[N_MAX];
    unsigned char msgs32[N_MAX*32];
    unsigned char sigs64[N_MAX*64];
    unsigned char aggsig[32*(N_MAX + 1) + 17];
    size_t aggsig_len = sizeof(aggsig);

    size_t n = testrand_int(N_MAX + 1);
    size_t n_initial = testrand_int(n + 1);
    size_t n_new = n - n_initial;
    test_schnorrsig_aggregate_input_helper(pubkeys, msgs32, sigs64, n);

    /* Aggregate the first n_initial of them */
    CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, n_initial));
    /* Make sure that the aggregate signature verifies */
    CHECK(aggsig_len == 32*(n_initial + 1));
    CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n_initial, aggsig, aggsig_len));
    /* Aggregate the remaining n_new many signatures to the already existing ones */
    aggsig_len = sizeof(aggsig);
    secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[n_initial*64], n_initial, n_new);
    /* Make sure that the aggregate signature verifies */
    CHECK(aggsig_len == 32*(n + 1));
    CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len));

    /* Check that a direct aggregation of the n sigs yields an identical aggsig */
    {
        unsigned char aggsig2[sizeof(aggsig)];
        size_t aggsig_len2 = sizeof(aggsig2);
        CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig2, &aggsig_len2, pubkeys, msgs32, sigs64, n));
        CHECK(aggsig_len == aggsig_len2);
        CHECK(secp256k1_memcmp_var(aggsig, aggsig2, aggsig_len) == 0);
    }
}

/* This tests the verification test vectors from
 * https://github.com/BlockstreamResearch/cross-input-aggregation/blob/master/hacspec-halfagg/tests/tests.rs#L78 . */
void test_schnorrsig_aggverify_spec_vectors(void) {
    /* Test vector 0 */
    {
        size_t n = 0;
        const unsigned char aggsig[32] = {
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
        };
        size_t aggsig_len = sizeof(aggsig);
        CHECK(secp256k1_schnorrsig_aggverify(CTX, NULL, NULL, n, aggsig, aggsig_len));
    }
    /* Test vector 1 */
    {
        size_t n = 1;
        const unsigned char pubkeys_ser[1*32] = {
            0x1b, 0x84, 0xc5, 0x56, 0x7b, 0x12, 0x64, 0x40,
            0x99, 0x5d, 0x3e, 0xd5, 0xaa, 0xba, 0x05, 0x65,
            0xd7, 0x1e, 0x18, 0x34, 0x60, 0x48, 0x19, 0xff,
            0x9c, 0x17, 0xf5, 0xe9, 0xd5, 0xdd, 0x07, 0x8f
        };
        secp256k1_xonly_pubkey pubkeys[1];
        const unsigned char msgs32[1*32] = {
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02
        };
        const unsigned char aggsig[1*32+32] = {
            0xb0, 0x70, 0xaa, 0xfc, 0xea, 0x43, 0x9a, 0x4f,
            0x6f, 0x1b, 0xbf, 0xc2, 0xeb, 0x66, 0xd2, 0x9d,
            0x24, 0xb0, 0xca, 0xb7, 0x4d, 0x6b, 0x74, 0x5c,
            0x3c, 0xfb, 0x00, 0x9c, 0xc8, 0xfe, 0x4a, 0xa8,
            0x0e, 0x06, 0x6c, 0x34, 0x81, 0x99, 0x36, 0x54,
            0x9f, 0xf4, 0x9b, 0x6f, 0xd4, 0xd4, 0x1e, 0xdf,
            0xc4, 0x01, 0xa3, 0x67, 0xb8, 0x7d, 0xdd, 0x59,
            0xfe, 0xe3, 0x81, 0x77, 0x96, 0x1c, 0x22, 0x5f,
        };
        size_t aggsig_len = sizeof(aggsig);
        size_t i;
        for (i = 0; i < n; ++i) {
            CHECK(secp256k1_xonly_pubkey_parse(CTX, &pubkeys[i], &pubkeys_ser[i*32]));
        }
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len));
    }
    /* Test vector 2 */
    {
        size_t n = 2;
        const unsigned char pubkeys_ser[2*32] = {
            0x1b, 0x84, 0xc5, 0x56, 0x7b, 0x12, 0x64, 0x40,
            0x99, 0x5d, 0x3e, 0xd5, 0xaa, 0xba, 0x05, 0x65,
            0xd7, 0x1e, 0x18, 0x34, 0x60, 0x48, 0x19, 0xff,
            0x9c, 0x17, 0xf5, 0xe9, 0xd5, 0xdd, 0x07, 0x8f,

            0x46, 0x27, 0x79, 0xad, 0x4a, 0xad, 0x39, 0x51,
            0x46, 0x14, 0x75, 0x1a, 0x71, 0x08, 0x5f, 0x2f,
            0x10, 0xe1, 0xc7, 0xa5, 0x93, 0xe4, 0xe0, 0x30,
            0xef, 0xb5, 0xb8, 0x72, 0x1c, 0xe5, 0x5b, 0x0b,
        };
        secp256k1_xonly_pubkey pubkeys[2];
        const unsigned char msgs32[2*32] = {
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,
            0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02, 0x02,

            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
            0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05, 0x05,
        };
        const unsigned char aggsig[2*32+32] = {
            0xb0, 0x70, 0xaa, 0xfc, 0xea, 0x43, 0x9a, 0x4f,
            0x6f, 0x1b, 0xbf, 0xc2, 0xeb, 0x66, 0xd2, 0x9d,
            0x24, 0xb0, 0xca, 0xb7, 0x4d, 0x6b, 0x74, 0x5c,
            0x3c, 0xfb, 0x00, 0x9c, 0xc8, 0xfe, 0x4a, 0xa8,
            0xa3, 0xaf, 0xbd, 0xb4, 0x5a, 0x6a, 0x34, 0xbf,
            0x7c, 0x8c, 0x00, 0xf1, 0xb6, 0xd7, 0xe7, 0xd3,
            0x75, 0xb5, 0x45, 0x40, 0xf1, 0x37, 0x16, 0xc8,
            0x7b, 0x62, 0xe5, 0x1e, 0x2f, 0x4f, 0x22, 0xff,
            0xbf, 0x89, 0x13, 0xec, 0x53, 0x22, 0x6a, 0x34,
            0x89, 0x2d, 0x60, 0x25, 0x2a, 0x70, 0x52, 0x61,
            0x4c, 0xa7, 0x9a, 0xe9, 0x39, 0x98, 0x68, 0x28,
            0xd8, 0x1d, 0x23, 0x11, 0x95, 0x73, 0x71, 0xad,
        };
        size_t aggsig_len = sizeof(aggsig);
        size_t i;
        for (i = 0; i < n; ++i) {
            CHECK(secp256k1_xonly_pubkey_parse(CTX, &pubkeys[i], &pubkeys_ser[i*32]));
        }
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len));
    }
}

static void test_schnorrsig_aggregate_api(void) {
    size_t n = testrand_int(N_MAX + 1);
    size_t n_initial = testrand_int(n + 1);
    size_t n_new = n - n_initial;

    /* Test preparation. */
    secp256k1_xonly_pubkey pubkeys[N_MAX];
    unsigned char msgs32[N_MAX*32];
    unsigned char sigs64[N_MAX*64];
    unsigned char aggsig[32*(N_MAX + 1)];
    test_schnorrsig_aggregate_input_helper(pubkeys, msgs32, sigs64, n);

    /* Test body 1: Check API of function aggregate. */
    {
        /* Should not accept NULL for aggsig or aggsig length */
        size_t aggsig_len = sizeof(aggsig);
        CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, NULL, &aggsig_len, pubkeys, msgs32, sigs64, n_initial));
        CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, aggsig, NULL, pubkeys, msgs32, sigs64, n_initial));
        /* Should not accept NULL for keys, messages, or signatures if n_initial is not 0 */
        if (n_initial != 0) {
            CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, NULL, msgs32, sigs64, n_initial));
            CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, NULL, sigs64, n_initial));
            CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, NULL, n_initial));
        }
    }

    /* Test body 2: Check API of function inc_aggregate. */
    {
        size_t aggsig_len = sizeof(aggsig);
        CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, n_initial));
        aggsig_len = 32*(n+1);
        /* Should not accept NULL for aggsig or aggsig length */
        CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, NULL, &aggsig_len, pubkeys, msgs32, &sigs64[n_initial*64], n_initial, n_new));
        CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, NULL, pubkeys, msgs32, &sigs64[n_initial*64], n_initial, n_new));
        /* Should not accept NULL for keys or messages if n is not 0 */
        if (n != 0) {
            CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, NULL, msgs32, &sigs64[n_initial*64], n_initial, n_new));
            CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, NULL, &sigs64[n_initial*64], n_initial, n_new));
        }
        /* Should not accept NULL for new_sigs64 if n_new is not 0 */
        if (n_new != 0) {
            CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, NULL, n_initial, n_new));
        }
        /* Should not accept overflowing number of sigs. */
        CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[n_initial*64], SIZE_MAX, SIZE_MAX));
        if (n_initial > 0) {
            CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[n_initial*64], n_initial, SIZE_MAX));
        }
        /* Should reject if aggsig_len is too small. */
        aggsig_len = 32*n;
        CHECK(secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[n_initial*64], n_initial, n_new) == 0);
        aggsig_len = 32*(n+1) - 1;
        CHECK(secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[n_initial*64], n_initial, n_new) == 0);
    }

    /* Test body 3: Check API of function aggverify. */
    {
        size_t aggsig_len = sizeof(aggsig);
        CHECK(secp256k1_schnorrsig_inc_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, &sigs64[n_initial*64], n_initial, n_new));
        /* Should not accept NULL for keys or messages if n is not 0 */
        if (n != 0) {
            CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggverify(CTX, NULL, msgs32, n, aggsig, aggsig_len));
            CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggverify(CTX, pubkeys, NULL, n, aggsig, aggsig_len));
        }
        /* Should never accept NULL the aggsig */
        CHECK_ILLEGAL(CTX, secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, NULL, aggsig_len));
        /* Should reject for invalid aggsig_len. */
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len + 1) == 0);
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len - 1) == 0);
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len + 32) == 0);
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len - 32) == 0);
    }
}

/* In this test, we make sure that trivial attempts to break
 * the security of verification do not work. */
static void test_schnorrsig_aggregate_unforge(void) {
    secp256k1_xonly_pubkey pubkeys[N_MAX];
    unsigned char msgs32[N_MAX*32];
    unsigned char sigs64[N_MAX*64];
    unsigned char aggsig[32*(N_MAX + 1)];

    size_t n = testrand_int(N_MAX + 1);

    /* Test 1: We fix a set of n messages and compute
     * a random aggsig for them. This should not verify. */
    test_schnorrsig_aggregate_input_helper(pubkeys, msgs32, sigs64, n);
    {
        size_t aggsig_len = sizeof(aggsig);
        size_t i;
        /* Sample aggsig randomly */
        for (i = 0; i < n + 1; ++i) {
            testrand256(&aggsig[i*32]);
        }
        /* Make sure that it does not verify */
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len) == 0);
    }

    /* Test 2: We fix a set of n messages and compute valid
     * signatures for all but one. The resulting aggregate signature
     * should not verify. */
    test_schnorrsig_aggregate_input_helper(pubkeys, msgs32, sigs64, n);
    if (n > 0) {
        size_t aggsig_len = sizeof(aggsig);
        /* Replace a randomly chosen real sig with a random one. */
        size_t k = testrand_int(n);
        testrand256(&sigs64[k*64]);
        testrand256(&sigs64[k*64+32]);
        /* Aggregate the n signatures */
        CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, n));
        /* Make sure the result does not verify */
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len) == 0);
    }

    /* Test 3: We generate a valid aggregate signature and then
     * change one of the messages. This should not verify. */
    test_schnorrsig_aggregate_input_helper(pubkeys, msgs32, sigs64, n);
    if (n > 0) {
        size_t aggsig_len = sizeof(aggsig);
        size_t k;
        /* Aggregate the n signatures */
        CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, n));
        /* Change one of the messages */
        k = testrand_int(32*n);
        msgs32[k] = msgs32[k]^0xff;
        /* Make sure the result does not verify */
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len) == 0);
    }
}

/* In this test, we make sure that the algorithms properly reject
 * for overflowing and non parseable values. */
static void test_schnorrsig_aggregate_overflow(void) {
    secp256k1_xonly_pubkey pubkeys[N_MAX];
    unsigned char msgs32[N_MAX*32];
    unsigned char sigs64[N_MAX*64];
    unsigned char aggsig[32*(N_MAX + 1)];
    size_t n = testrand_int(N_MAX + 1);

    /* We check that verification returns 0 if the s in aggsig overflows. */
    test_schnorrsig_aggregate_input_helper(pubkeys, msgs32, sigs64, n);
    {
        size_t aggsig_len = sizeof(aggsig);
        /* Aggregate */
        CHECK(secp256k1_schnorrsig_aggregate(CTX, aggsig, &aggsig_len, pubkeys, msgs32, sigs64, n));
        /* Make s in the aggsig overflow */
        memset(&aggsig[n*32], 0xFF, 32);
        /* Should not verify */
        CHECK(secp256k1_schnorrsig_aggverify(CTX, pubkeys, msgs32, n, aggsig, aggsig_len) == 0);
    }
}

static void run_schnorrsig_halfagg_tests(void) {
    int i;

    test_schnorrsig_sha256_tagged_aggregate();
    test_schnorrsig_aggverify_spec_vectors();

    for (i = 0; i < COUNT; i++) {
        test_schnorrsig_aggregate();
        test_schnorrsig_aggregate_api();
        test_schnorrsig_aggregate_unforge();
        test_schnorrsig_aggregate_overflow();
    }
}

#undef N_MAX

#endif
