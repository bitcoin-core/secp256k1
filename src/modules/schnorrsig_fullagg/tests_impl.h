/***********************************************************************
 * Copyright (c) 2025 Fabian Jahr                                      *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_FULLAGG_TESTS_IMPL_H
#define SECP256K1_MODULE_SCHNORRSIG_FULLAGG_TESTS_IMPL_H

#include <stdlib.h>
#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_schnorrsig_fullagg.h"

#include "../../scalar.h"
#include "../../field.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../util.h"

static int create_keypair_and_pk_fullagg(secp256k1_keypair *keypair, secp256k1_pubkey *pk, const unsigned char *sk) {
    int ret;
    secp256k1_keypair keypair_tmp;
    ret = secp256k1_keypair_create(CTX, &keypair_tmp, sk);
    ret &= secp256k1_keypair_pub(CTX, pk, &keypair_tmp);
    if (keypair != NULL) {
        *keypair = keypair_tmp;
    }
    return ret;
}

/* Simple test with three signers */
static void fullagg_simple_test_internal(void) {
    unsigned char sk[3][32];
    secp256k1_keypair keypair[3];
    secp256k1_fullagg_pubnonce pubnonce[3];
    const secp256k1_fullagg_pubnonce *pubnonce_ptr[3];
    secp256k1_fullagg_aggnonce aggnonce;
    unsigned char msg[3][32];
    unsigned char session_secrand[3][32];
    secp256k1_fullagg_secnonce secnonce[3];
    secp256k1_pubkey pk[3];
    const secp256k1_pubkey *pk_ptr[3];
    const unsigned char *msg_ptr[3];
    secp256k1_fullagg_partial_sig partial_sig[3];
    const secp256k1_fullagg_partial_sig *partial_sig_ptr[3];
    unsigned char final_sig[64];
    secp256k1_fullagg_session session;
    int i;
    const secp256k1_pubkey *pk_wrong_order[3];
    int sign_success;
    int retry_count = 0;

    testrand256(msg[0]);
    testrand256(msg[1]);
    testrand256(msg[2]);
    
    for (i = 0; i < 3; i++) {
        testrand256(sk[i]);
        pk_ptr[i] = &pk[i];
        msg_ptr[i] = msg[i];
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];

        CHECK(create_keypair_and_pk_fullagg(&keypair[i], &pk[i], sk[i]));
    }

    /* Try up to 3 times in case we get unlucky with infinity aggregate nonces */
    sign_success = 0;
    while (!sign_success && retry_count < 3) {
        retry_count++;
        
        /* Generate nonces */
        for (i = 0; i < 3; i++) {
            testrand256(session_secrand[i]);
            CHECK(secp256k1_fullagg_nonce_gen(CTX, &secnonce[i], &pubnonce[i], session_secrand[i], 
                                              sk[i], &pk[i], msg[i], NULL) == 1);
        }

        /* Aggregate nonces */
        CHECK(secp256k1_fullagg_nonce_agg(CTX, &aggnonce, pubnonce_ptr, 3) == 1);
        
        /* Initialize session */
        CHECK(secp256k1_fullagg_session_init(CTX, &session, &aggnonce, pk_ptr, msg_ptr, 
                                             pubnonce_ptr, 3) == 1);

        /* The signers create their partial signature */
        sign_success = 1;
        for (i = 0; i < 3; i++) {
            if (secp256k1_fullagg_partial_sign(CTX, &partial_sig[i], &secnonce[i], 
                                               &keypair[i], &session, pk_ptr, msg_ptr, 
                                               pubnonce_ptr, i) != 1) {
                sign_success = 0;
                break;
            }
            /* Verify partial signature */
            if (secp256k1_fullagg_partial_sig_verify(CTX, &partial_sig[i], &pubnonce[i], 
                                                     &pk[i], &session, pk_ptr, msg_ptr, i) != 1) {
                sign_success = 0;
                break;
            }
        }
    }
    CHECK(sign_success);

    /* Aggregate partial signatures */
    CHECK(secp256k1_fullagg_partial_sig_agg(CTX, final_sig, &session, partial_sig_ptr, 3) == 1);
    
    /* Verify the aggregate signature */
    CHECK(secp256k1_fullagg_verify(CTX, final_sig, pk_ptr, msg_ptr, 3) == 1);
    
    /* Test that verification fails with wrong message */
    msg[0][0] ^= 1;  /* Maleate the message */
    CHECK(secp256k1_fullagg_verify(CTX, final_sig, pk_ptr, msg_ptr, 3) == 0);
    msg[0][0] ^= 1;  /* Restore original message */
    
    /* Test that verification fails with wrong public key order */
    pk_wrong_order[0] = &pk[1];
    pk_wrong_order[1] = &pk[0];
    pk_wrong_order[2] = &pk[2];
    CHECK(secp256k1_fullagg_verify(CTX, final_sig, pk_wrong_order, msg_ptr, 3) == 0);
    
    /* Test that verification fails with incomplete list */
    CHECK(secp256k1_fullagg_verify(CTX, final_sig, pk_ptr, msg_ptr, 2) == 0);
}

/* Test API parameter validation */
static void fullagg_api_tests(void) {
    secp256k1_fullagg_partial_sig partial_sig[2];
    const secp256k1_fullagg_partial_sig *partial_sig_ptr[2];
    unsigned char pre_sig[64];
    unsigned char sk[2][32];
    secp256k1_keypair keypair[2];
    unsigned char zeros132[132] = { 0 };
    unsigned char session_secrand[2][32];
    secp256k1_fullagg_secnonce secnonce[2];
    secp256k1_fullagg_pubnonce pubnonce[2];
    const secp256k1_fullagg_pubnonce *pubnonce_ptr[2];
    unsigned char pubnonce_ser[66];
    secp256k1_fullagg_aggnonce aggnonce;
    unsigned char aggnonce_ser[66];
    unsigned char msg[2][32];
    const unsigned char *msg_ptr[2];
    secp256k1_fullagg_session session;
    secp256k1_pubkey pk[2];
    const secp256k1_pubkey *pk_ptr[2];
    int i;

    for (i = 0; i < 2; i++) {
        pk_ptr[i] = &pk[i];
        msg_ptr[i] = msg[i];
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
        testrand256(session_secrand[i]);
        testrand256(sk[i]);
        testrand256(msg[i]);
        CHECK(create_keypair_and_pk_fullagg(&keypair[i], &pk[i], sk[i]));
    }

    /* Nonce generation */
    CHECK(secp256k1_fullagg_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_secrand[0], 
                                      sk[0], &pk[0], msg[0], NULL) == 1);
    /* Check that session_secrand is zeroed */
    CHECK(secp256k1_memcmp_var(session_secrand[0], zeros132, sizeof(session_secrand[0])) == 0);

    /* session_secrand = 0 is disallowed */
    memset(session_secrand[0], 0, sizeof(session_secrand[0]));
    CHECK(secp256k1_fullagg_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_secrand[0], 
                                      sk[0], &pk[0], msg[0], NULL) == 0);

    /* Test NULL parameters */
    testrand256(session_secrand[0]);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_nonce_gen(CTX, NULL, &pubnonce[0], session_secrand[0], 
                                                   sk[0], &pk[0], msg[0], NULL));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_nonce_gen(CTX, &secnonce[0], NULL, session_secrand[0], 
                                                   sk[0], &pk[0], msg[0], NULL));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_nonce_gen(CTX, &secnonce[0], &pubnonce[0], NULL, 
                                                   sk[0], &pk[0], msg[0], NULL));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_nonce_gen(CTX, &secnonce[0], &pubnonce[0], session_secrand[0], 
                                                   sk[0], NULL, msg[0], NULL));

    /* Generate valid nonces for both signers */
    for (i = 0; i < 2; i++) {
        testrand256(session_secrand[i]);
        CHECK(secp256k1_fullagg_nonce_gen(CTX, &secnonce[i], &pubnonce[i], session_secrand[i], 
                                          sk[i], &pk[i], msg[i], NULL) == 1);
    }

    /* Serialize and parse public nonces */
    CHECK(secp256k1_fullagg_pubnonce_serialize(CTX, pubnonce_ser, &pubnonce[0]) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_pubnonce_serialize(CTX, NULL, &pubnonce[0]));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_pubnonce_serialize(CTX, pubnonce_ser, NULL));

    CHECK(secp256k1_fullagg_pubnonce_parse(CTX, &pubnonce[0], pubnonce_ser) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_pubnonce_parse(CTX, NULL, pubnonce_ser));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_pubnonce_parse(CTX, &pubnonce[0], NULL));

    /* Nonce aggregation */
    CHECK(secp256k1_fullagg_nonce_agg(CTX, &aggnonce, pubnonce_ptr, 2) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_nonce_agg(CTX, NULL, pubnonce_ptr, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_nonce_agg(CTX, &aggnonce, NULL, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_nonce_agg(CTX, &aggnonce, pubnonce_ptr, 0));

    /* Serialize and parse aggregate nonces */
    CHECK(secp256k1_fullagg_aggnonce_serialize(CTX, aggnonce_ser, &aggnonce) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_aggnonce_serialize(CTX, NULL, &aggnonce));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_aggnonce_serialize(CTX, aggnonce_ser, NULL));

    CHECK(secp256k1_fullagg_aggnonce_parse(CTX, &aggnonce, aggnonce_ser) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_aggnonce_parse(CTX, NULL, aggnonce_ser));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_aggnonce_parse(CTX, &aggnonce, NULL));

    /* Session initialization */
    CHECK(secp256k1_fullagg_session_init(CTX, &session, &aggnonce, pk_ptr, msg_ptr, 
                                         pubnonce_ptr, 2) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_session_init(CTX, NULL, &aggnonce, pk_ptr, msg_ptr, 
                                                      pubnonce_ptr, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_session_init(CTX, &session, NULL, pk_ptr, msg_ptr, 
                                                      pubnonce_ptr, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_session_init(CTX, &session, &aggnonce, NULL, msg_ptr, 
                                                      pubnonce_ptr, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_session_init(CTX, &session, &aggnonce, pk_ptr, NULL, 
                                                      pubnonce_ptr, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_session_init(CTX, &session, &aggnonce, pk_ptr, msg_ptr, 
                                                      NULL, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_session_init(CTX, &session, &aggnonce, pk_ptr, msg_ptr, 
                                                      pubnonce_ptr, 0));

    /* Partial signing */
    {
        int sign_success = 1;
        for (i = 0; i < 2; i++) {
            secp256k1_fullagg_secnonce secnonce_tmp;
            memcpy(&secnonce_tmp, &secnonce[i], sizeof(secnonce_tmp));
            if (secp256k1_fullagg_partial_sign(CTX, &partial_sig[i], &secnonce_tmp, &keypair[i], 
                                              &session, pk_ptr, msg_ptr, pubnonce_ptr, i) != 1) {
                sign_success = 0;
                break;
            }
            /* The secnonce is set to 0 and following signing attempts fail */
            CHECK(secp256k1_memcmp_var(&secnonce_tmp, zeros132, sizeof(secnonce_tmp)) == 0);
            CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sign(CTX, &partial_sig[i], &secnonce_tmp, 
                                                              &keypair[i], &session, pk_ptr, msg_ptr, 
                                                              pubnonce_ptr, i));
        }
        
        /* If signing failed due to infinity aggregate nonce, regenerate and try once more */
        if (!sign_success) {
            /* Generate new nonces */
            for (i = 0; i < 2; i++) {
                testrand256(session_secrand[i]);
                CHECK(secp256k1_fullagg_nonce_gen(CTX, &secnonce[i], &pubnonce[i], session_secrand[i], 
                                                  sk[i], &pk[i], msg[i], NULL) == 1);
            }
            
            /* Re-aggregate and re-initialize session */
            CHECK(secp256k1_fullagg_nonce_agg(CTX, &aggnonce, pubnonce_ptr, 2) == 1);
            CHECK(secp256k1_fullagg_session_init(CTX, &session, &aggnonce, pk_ptr, msg_ptr, 
                                                 pubnonce_ptr, 2) == 1);
            
            /* Try signing again */
            for (i = 0; i < 2; i++) {
                secp256k1_fullagg_secnonce secnonce_tmp;
                memcpy(&secnonce_tmp, &secnonce[i], sizeof(secnonce_tmp));
                CHECK(secp256k1_fullagg_partial_sign(CTX, &partial_sig[i], &secnonce_tmp, &keypair[i], 
                                                     &session, pk_ptr, msg_ptr, pubnonce_ptr, i) == 1);
                /* The secnonce is set to 0 and subsequent signing attempts fail */
                CHECK(secp256k1_memcmp_var(&secnonce_tmp, zeros132, sizeof(secnonce_tmp)) == 0);
                CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sign(CTX, &partial_sig[i], &secnonce_tmp, 
                                                                  &keypair[i], &session, pk_ptr, msg_ptr, 
                                                                  pubnonce_ptr, i));
            }
        }
    }

    /* Regenerate nonces and sign again with fresh secnonces */
    {
        int sign_success = 0;
        int retry_count = 0;
        /* Try up to 3 times in case we get unlucky with infinity aggregate nonces */
        while (!sign_success && retry_count < 3) {
            retry_count++;
            
            /* Generate new nonces */
            for (i = 0; i < 2; i++) {
                testrand256(session_secrand[i]);
                CHECK(secp256k1_fullagg_nonce_gen(CTX, &secnonce[i], &pubnonce[i], session_secrand[i], 
                                                  sk[i], &pk[i], msg[i], NULL) == 1);
            }
            
            /* Re-aggregate nonces and re-initialize session with new nonces */
            CHECK(secp256k1_fullagg_nonce_agg(CTX, &aggnonce, pubnonce_ptr, 2) == 1);
            CHECK(secp256k1_fullagg_session_init(CTX, &session, &aggnonce, pk_ptr, msg_ptr, 
                                                 pubnonce_ptr, 2) == 1);
            
            /* Try signing with the fresh nonces */
            sign_success = 1;
            for (i = 0; i < 2; i++) {
                if (secp256k1_fullagg_partial_sign(CTX, &partial_sig[i], &secnonce[i], &keypair[i], 
                                                   &session, pk_ptr, msg_ptr, pubnonce_ptr, i) != 1) {
                    sign_success = 0;
                    break;
                }
            }
        }
        CHECK(sign_success); /* Should succeed within 3 attempts */
    }

    /** Partial signature verification **/
    CHECK(secp256k1_fullagg_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pk[0], 
                                               &session, pk_ptr, msg_ptr, 0) == 1);
    CHECK(secp256k1_fullagg_partial_sig_verify(CTX, &partial_sig[1], &pubnonce[1], &pk[1], 
                                               &session, pk_ptr, msg_ptr, 1) == 1);
    /* Wrong signer index */
    CHECK(secp256k1_fullagg_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pk[0], 
                                               &session, pk_ptr, msg_ptr, 1) == 0);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sig_verify(CTX, NULL, &pubnonce[0], &pk[0], 
                                                            &session, pk_ptr, msg_ptr, 0));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sig_verify(CTX, &partial_sig[0], NULL, &pk[0], 
                                                            &session, pk_ptr, msg_ptr, 0));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], NULL, 
                                                            &session, pk_ptr, msg_ptr, 0));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sig_verify(CTX, &partial_sig[0], &pubnonce[0], &pk[0], 
                                                            NULL, pk_ptr, msg_ptr, 0));

    /** Signature aggregation **/
    CHECK(secp256k1_fullagg_partial_sig_agg(CTX, pre_sig, &session, partial_sig_ptr, 2) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sig_agg(CTX, NULL, &session, partial_sig_ptr, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sig_agg(CTX, pre_sig, NULL, partial_sig_ptr, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sig_agg(CTX, pre_sig, &session, NULL, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_partial_sig_agg(CTX, pre_sig, &session, partial_sig_ptr, 0));

    /** Verification **/
    CHECK(secp256k1_fullagg_verify(CTX, pre_sig, pk_ptr, msg_ptr, 2) == 1);
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_verify(CTX, NULL, pk_ptr, msg_ptr, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_verify(CTX, pre_sig, NULL, msg_ptr, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_verify(CTX, pre_sig, pk_ptr, NULL, 2));
    CHECK_ILLEGAL(CTX, secp256k1_fullagg_verify(CTX, pre_sig, pk_ptr, msg_ptr, 0));
}

/* Test with counter-based nonce generation */
static void fullagg_nonce_gen_counter_test(void) {
    unsigned char sk[2][32];
    secp256k1_keypair keypair[2];
    secp256k1_pubkey pk[2];
    const secp256k1_pubkey *pk_ptr[2];
    secp256k1_fullagg_pubnonce pubnonce[2];
    const secp256k1_fullagg_pubnonce *pubnonce_ptr[2];
    secp256k1_fullagg_aggnonce aggnonce;
    secp256k1_fullagg_secnonce secnonce[2];
    secp256k1_fullagg_session session;
    secp256k1_fullagg_partial_sig partial_sig[2];
    const secp256k1_fullagg_partial_sig *partial_sig_ptr[2];
    unsigned char msg[2][32];
    const unsigned char *msg_ptr[2];
    unsigned char final_sig[64];
    uint64_t nonrepeating_cnt = 0;
    int i;
    int sign_success;
    int retry_count;

    for (i = 0; i < 2; i++) {
        testrand256(sk[i]);
        testrand256(msg[i]);
        CHECK(create_keypair_and_pk_fullagg(&keypair[i], &pk[i], sk[i]));
        pk_ptr[i] = &pk[i];
        msg_ptr[i] = msg[i];
        pubnonce_ptr[i] = &pubnonce[i];
        partial_sig_ptr[i] = &partial_sig[i];
    }

    sign_success = 0;
    retry_count = 0;
    while (!sign_success && retry_count < 3) {
        retry_count++;
        
        /* Generate nonces using counter */
        for (i = 0; i < 2; i++) {
            CHECK(secp256k1_fullagg_nonce_gen_counter(CTX, &secnonce[i], &pubnonce[i], 
                                                      nonrepeating_cnt + i, &keypair[i], 
                                                      msg[i], NULL) == 1);
        }
        nonrepeating_cnt += 2; /* Increment for next attempt if needed */

        /* Complete the protocol */
        CHECK(secp256k1_fullagg_nonce_agg(CTX, &aggnonce, pubnonce_ptr, 2) == 1);
        CHECK(secp256k1_fullagg_session_init(CTX, &session, &aggnonce, pk_ptr, msg_ptr, 
                                             pubnonce_ptr, 2) == 1);

        sign_success = 1;
        for (i = 0; i < 2; i++) {
            if (secp256k1_fullagg_partial_sign(CTX, &partial_sig[i], &secnonce[i], &keypair[i], 
                                               &session, pk_ptr, msg_ptr, pubnonce_ptr, i) != 1) {
                sign_success = 0;
                break;
            }
        }
    }
    CHECK(sign_success);

    CHECK(secp256k1_fullagg_partial_sig_agg(CTX, final_sig, &session, partial_sig_ptr, 2) == 1);
    CHECK(secp256k1_fullagg_verify(CTX, final_sig, pk_ptr, msg_ptr, 2) == 1);
}

/* Test serialization round-trip */
static void fullagg_serialization_test(void) {
    secp256k1_fullagg_pubnonce pubnonce, pubnonce2;
    secp256k1_fullagg_aggnonce aggnonce, aggnonce2;
    secp256k1_fullagg_partial_sig partial_sig, partial_sig2;
    unsigned char pubnonce_ser[66];
    unsigned char aggnonce_ser[66];
    unsigned char partial_sig_ser[32];
    unsigned char session_secrand[32];
    unsigned char sk[32];
    unsigned char msg[32];
    secp256k1_pubkey pk;
    secp256k1_fullagg_secnonce secnonce;
    secp256k1_scalar s;
    const secp256k1_fullagg_pubnonce *pubnonce_ptr;

    testrand256(sk);
    testrand256(msg);
    testrand256(session_secrand);
    CHECK(create_keypair_and_pk_fullagg(NULL, &pk, sk));

    /* Test pubnonce serialization */
    CHECK(secp256k1_fullagg_nonce_gen(CTX, &secnonce, &pubnonce, session_secrand, 
                                      sk, &pk, msg, NULL) == 1);
    CHECK(secp256k1_fullagg_pubnonce_serialize(CTX, pubnonce_ser, &pubnonce) == 1);
    CHECK(secp256k1_fullagg_pubnonce_parse(CTX, &pubnonce2, pubnonce_ser) == 1);
    CHECK(secp256k1_memcmp_var(&pubnonce, &pubnonce2, sizeof(pubnonce)) == 0);

    /* Test aggnonce serialization */
    pubnonce_ptr = &pubnonce;
    CHECK(secp256k1_fullagg_nonce_agg(CTX, &aggnonce, &pubnonce_ptr, 1) == 1);
    CHECK(secp256k1_fullagg_aggnonce_serialize(CTX, aggnonce_ser, &aggnonce) == 1);
    CHECK(secp256k1_fullagg_aggnonce_parse(CTX, &aggnonce2, aggnonce_ser) == 1);
    CHECK(secp256k1_memcmp_var(&aggnonce, &aggnonce2, sizeof(aggnonce)) == 0);

    /* Test partial_sig serialization */
    testutil_random_scalar_order_test(&s);
    secp256k1_fullagg_partial_sig_save(&partial_sig, &s);
    CHECK(secp256k1_fullagg_partial_sig_serialize(CTX, partial_sig_ser, &partial_sig) == 1);
    CHECK(secp256k1_fullagg_partial_sig_parse(CTX, &partial_sig2, partial_sig_ser) == 1);
    CHECK(secp256k1_memcmp_var(&partial_sig, &partial_sig2, sizeof(partial_sig)) == 0);
}

static void fullagg_duplicate_pubnonce_test(void) {
    unsigned char sk[32];
    secp256k1_keypair keypair;
    secp256k1_pubkey pk;
    const secp256k1_pubkey *pk_ptr[2];
    secp256k1_fullagg_pubnonce pubnonce[2];
    const secp256k1_fullagg_pubnonce *pubnonce_ptr[2];
    secp256k1_fullagg_aggnonce aggnonce;
    secp256k1_fullagg_secnonce secnonce;
    secp256k1_fullagg_session session;
    secp256k1_fullagg_partial_sig partial_sig;
    unsigned char msg[2][32];
    const unsigned char *msg_ptr[2];
    unsigned char session_secrand[32];
    
    testrand256(sk);
    testrand256(msg[0]);
    testrand256(msg[1]);
    CHECK(create_keypair_and_pk_fullagg(&keypair, &pk, sk));
    
    testrand256(session_secrand);
    CHECK(secp256k1_fullagg_nonce_gen(CTX, &secnonce, &pubnonce[0], session_secrand, 
                                      sk, &pk, msg[0], NULL) == 1);
    
    /* Duplicate the pubnonce */
    pubnonce[1] = pubnonce[0];
    
    pk_ptr[0] = &pk;
    pk_ptr[1] = &pk;
    msg_ptr[0] = msg[0];
    msg_ptr[1] = msg[1];
    pubnonce_ptr[0] = &pubnonce[0];
    pubnonce_ptr[1] = &pubnonce[1];
    
    CHECK(secp256k1_fullagg_nonce_agg(CTX, &aggnonce, pubnonce_ptr, 2) == 1);
    CHECK(secp256k1_fullagg_session_init(CTX, &session, &aggnonce, pk_ptr, msg_ptr, 
                                         pubnonce_ptr, 2) == 1);
    
    /* Fails because R2 appears twice */
    CHECK(secp256k1_fullagg_partial_sign(CTX, &partial_sig, &secnonce, &keypair, 
                                         &session, pk_ptr, msg_ptr, pubnonce_ptr, 0) == 0);
}

/* --- Test registry --- */
REPEAT_TEST(fullagg_simple_test)

static const struct tf_test_entry tests_schnorrsig_fullagg[] = {
    CASE1(fullagg_simple_test),
    CASE1(fullagg_api_tests),
    CASE1(fullagg_nonce_gen_counter_test),
    CASE1(fullagg_serialization_test),
    CASE1(fullagg_duplicate_pubnonce_test),
};

#endif /* SECP256K1_MODULE_SCHNORRSIG_FULLAGG_TESTS_IMPL_H */
