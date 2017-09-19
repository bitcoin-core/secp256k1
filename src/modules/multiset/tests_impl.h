/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
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
    secp256k1_multiset_finalize_roller(ctx, hash1, (a)); \
    secp256k1_multiset_finalize_roller(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))==0); \
}

#define CHECK_NOTEQUAL(a,b) { \
    unsigned char hash1[32]; \
    unsigned char hash2[32]; \
    secp256k1_multiset_finalize_roller(ctx, hash1, (a)); \
    secp256k1_multiset_finalize_roller(ctx, hash2, (b)); \
    CHECK(memcmp(hash1,hash2,sizeof(hash1))!=0); \
}

static unsigned char data[DATACOUNT][DATALEN];
static secp256k1_roller rollers[DATACOUNT];

/* create random data and calculate rollers */
static void initdata(void) {
    int n,m;
    for(n=0; n < DATACOUNT; n++) {
        for(m=0; m < DATALEN/4; m++) {
            ((uint32_t*) data[n])[m] = secp256k1_rand32();
        }

        secp256k1_multiset_create_roller(ctx, &rollers[n], data[n], DATALEN);
    }
}

void test_unordered(void) {

    secp256k1_roller r1,r2,r3;

    memcpy(&r1, &rollers[0], 64);
    memcpy(&r2, &rollers[1], 64);

    secp256k1_multiset_add_roller(ctx, &r1, &rollers[6]);
    secp256k1_multiset_add_roller(ctx, &r2, &rollers[6]);

    CHECK_NOTEQUAL(&r1,&r2);
    secp256k1_multiset_add_roller(ctx, &r1, &rollers[1]);
    secp256k1_multiset_add_roller(ctx, &r2, &rollers[0]);
    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_init_roller(ctx, &r1);
    secp256k1_multiset_init_roller(ctx, &r2);
    secp256k1_multiset_init_roller(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);


    secp256k1_multiset_add_roller(ctx, &r1, &rollers[0]);
    secp256k1_multiset_add_roller(ctx, &r1, &rollers[1]);
    secp256k1_multiset_add_roller(ctx, &r1, &rollers[3]);

    secp256k1_multiset_add_roller(ctx, &r2, &rollers[3]);
    secp256k1_multiset_add_roller(ctx, &r2, &rollers[0]);
    secp256k1_multiset_add_roller(ctx, &r2, &rollers[1]);

    secp256k1_multiset_add_roller(ctx, &r3, &rollers[1]);
    secp256k1_multiset_add_roller(ctx, &r3, &rollers[0]);
    secp256k1_multiset_add_roller(ctx, &r3, &rollers[3]);

    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);

    secp256k1_multiset_add_roller(ctx, &r3, &rollers[3]);
    CHECK_NOTEQUAL(&r1,&r3);

}

void test_remove(void) {

    secp256k1_roller r1,r2,r3;

    secp256k1_multiset_init_roller(ctx, &r1);
    secp256k1_multiset_init_roller(ctx, &r2);
    secp256k1_multiset_init_roller(ctx, &r3);

    CHECK_EQUAL(&r1,&r2);

    secp256k1_multiset_add_roller   (ctx, &r1, &rollers[0]);
    secp256k1_multiset_add_roller   (ctx, &r1, &rollers[1]);
    secp256k1_multiset_add_roller   (ctx, &r1, &rollers[3]);
    secp256k1_multiset_add_roller   (ctx, &r1, &rollers[9]);
    secp256k1_multiset_add_roller   (ctx, &r1, &rollers[8]);

    secp256k1_multiset_add_roller   (ctx, &r2, &rollers[1]);
    secp256k1_multiset_add_roller   (ctx, &r2, &rollers[9]);
    secp256k1_multiset_add_roller   (ctx, &r2, &rollers[11]);
    secp256k1_multiset_add_roller   (ctx, &r2, &rollers[10]);
    secp256k1_multiset_add_roller   (ctx, &r2, &rollers[0]);
    secp256k1_multiset_remove_roller(ctx, &r2, &rollers[10]);
    secp256k1_multiset_add_roller   (ctx, &r2, &rollers[3]);
    secp256k1_multiset_add_roller   (ctx, &r2, &rollers[8]);
    secp256k1_multiset_remove_roller(ctx, &r2, &rollers[11]);

    secp256k1_multiset_add_roller   (ctx, &r3, &rollers[9]);
    secp256k1_multiset_add_roller   (ctx, &r3, &rollers[15]);
    secp256k1_multiset_add_roller   (ctx, &r3, &rollers[15]);
    secp256k1_multiset_add_roller   (ctx, &r3, &rollers[1]);
    secp256k1_multiset_add_roller   (ctx, &r3, &rollers[9]);
    secp256k1_multiset_remove_roller(ctx, &r3, &rollers[15]);
    secp256k1_multiset_add_roller   (ctx, &r3, &rollers[0]);
    secp256k1_multiset_remove_roller(ctx, &r3, &rollers[15]);
    secp256k1_multiset_remove_roller(ctx, &r3, &rollers[9]);
    secp256k1_multiset_add_roller   (ctx, &r3, &rollers[3]);
    secp256k1_multiset_add_roller   (ctx, &r3, &rollers[8]);

    CHECK_EQUAL(&r1,&r2);
    CHECK_EQUAL(&r1,&r3);

    secp256k1_multiset_remove_roller(ctx, &r3, &rollers[9]);
    CHECK_NOTEQUAL(&r1,&r3);
}

void run_multiset_tests(void) {

    initdata();

    /* test macros */
    CHECK_EQUAL(&rollers[0],&rollers[0]);
    CHECK_NOTEQUAL(&rollers[0],&rollers[1]);

    test_unordered();
    test_remove();

}

#endif
