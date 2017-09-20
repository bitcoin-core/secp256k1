/**********************************************************************
 * Copyright (c) 2017 Tomas van der Wansem                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_MODULE_MULTISET_TESTS_
#define _SECP256K1_MODULE_MULTISET_TESTS_


#include "include/secp256k1.h"
#include "include/secp256k1_multiset.h"
#include "util.h"
#include "testrand.h"

#define DATALEN   64*3
#define DATACOUNT 100


#define CHECK_EQUAL(a,b) { \
    unsigned char hash1[32]; \
    unsigned char hash2[32]; \
    secp256k1_multiset_finalize(ctx, hash1, (a)); \
    secp256k1_multiset_finalize(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))==0); \
}

#define CHECK_NOTEQUAL(a,b) { \
    unsigned char hash1[32]; \
    unsigned char hash2[32]; \
    secp256k1_multiset_finalize(ctx, hash1, (a)); \
    secp256k1_multiset_finalize(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))!=0); \
}

static unsigned char data[DATACOUNT][DATALEN];
static secp256k1_multiset multisets[DATACOUNT];

/* create random data and calculate multisets */
static void initdata(void) {
    int n,m;
    for(n=0; n < DATACOUNT; n++) {
        for(m=0; m < DATALEN/4; m++) {
            ((uint32_t*) data[n])[m] = secp256k1_rand32();
        }

        secp256k1_multiset_create(ctx, &multisets[n], data[n], DATALEN);
    }
}

void test_unordered(void) {

    secp256k1_multiset r1,r2,r3;

    memcpy(&r1, &multisets[0], 64);
    memcpy(&r2, &multisets[1], 64);

    secp256k1_multiset_add(ctx, &r1, &multisets[6]);
    secp256k1_multiset_add(ctx, &r2, &multisets[6]);

    CHECK_NOTEQUAL(&r1,&r2);
    secp256k1_multiset_add(ctx, &r1, &multisets[1]);
    secp256k1_multiset_add(ctx, &r2, &multisets[0]);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_add(ctx, &r1, &multisets[0]);
    secp256k1_multiset_add(ctx, &r1, &multisets[1]);
    secp256k1_multiset_add(ctx, &r1, &multisets[3]);

    secp256k1_multiset_add(ctx, &r2, &multisets[3]);
    secp256k1_multiset_add(ctx, &r2, &multisets[0]);
    secp256k1_multiset_add(ctx, &r2, &multisets[1]);

    secp256k1_multiset_add(ctx, &r3, &multisets[1]);
    secp256k1_multiset_add(ctx, &r3, &multisets[0]);
    secp256k1_multiset_add(ctx, &r3, &multisets[3]);

    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);

    secp256k1_multiset_add(ctx, &r3, &multisets[3]);
    CHECK_NOTEQUAL(&r1,&r3);

}

void test_remove(void) {

    secp256k1_multiset r1,r2,r3;

    secp256k1_multiset_init(ctx, &r1);
    secp256k1_multiset_init(ctx, &r2);
    secp256k1_multiset_init(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_add   (ctx, &r1, &multisets[0]);
    secp256k1_multiset_add   (ctx, &r1, &multisets[1]);
    secp256k1_multiset_add   (ctx, &r1, &multisets[3]);
    secp256k1_multiset_add   (ctx, &r1, &multisets[9]);
    secp256k1_multiset_add   (ctx, &r1, &multisets[8]);

    secp256k1_multiset_add   (ctx, &r2, &multisets[1]);
    secp256k1_multiset_add   (ctx, &r2, &multisets[9]);
    secp256k1_multiset_add   (ctx, &r2, &multisets[11]);
    secp256k1_multiset_add   (ctx, &r2, &multisets[10]);
    secp256k1_multiset_add   (ctx, &r2, &multisets[0]);
    secp256k1_multiset_remove(ctx, &r2, &multisets[10]);
    secp256k1_multiset_add   (ctx, &r2, &multisets[3]);
    secp256k1_multiset_add   (ctx, &r2, &multisets[8]);
    secp256k1_multiset_remove(ctx, &r2, &multisets[11]);

    secp256k1_multiset_add   (ctx, &r3, &multisets[9]);
    secp256k1_multiset_add   (ctx, &r3, &multisets[15]);
    secp256k1_multiset_add   (ctx, &r3, &multisets[15]);
    secp256k1_multiset_add   (ctx, &r3, &multisets[1]);
    secp256k1_multiset_add   (ctx, &r3, &multisets[9]);
    secp256k1_multiset_remove(ctx, &r3, &multisets[15]);
    secp256k1_multiset_add   (ctx, &r3, &multisets[0]);
    secp256k1_multiset_remove(ctx, &r3, &multisets[15]);
    secp256k1_multiset_remove(ctx, &r3, &multisets[9]);
    secp256k1_multiset_add   (ctx, &r3, &multisets[3]);
    secp256k1_multiset_add   (ctx, &r3, &multisets[8]);

    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);

    secp256k1_multiset_remove(ctx, &r3, &multisets[9]);
    CHECK_NOTEQUAL(&r1,&r3);
}

void run_multiset_tests(void) {

    initdata();

    /* test macros */
    CHECK_EQUAL(&multisets[0],&multisets[0]);
    CHECK_NOTEQUAL(&multisets[0],&multisets[1]);

    test_unordered();
    test_remove();

}

#endif
