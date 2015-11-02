/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_NUM_5X64_IMPL_
#define _SECP256K1_NUM_5X64_IMPL_

#include <string.h>

#include "num.h"
#include "num_5x64.h"
#include "util.h"

#include "num_native_impl.h"

static void secp256k1_num_debug_print(const char *name, const secp256k1_num *a) {
    int i;
    printf ("%s: 0x", name);
    for (i = 4; i >= 0; --i)
        printf("%016lx", a->data[i]);
    puts("");
}

static void secp256k1_num_get_bin(unsigned char *r, unsigned int rlen, const secp256k1_num *a) {
    uint64_t v;
    (void) rlen;
    VERIFY_CHECK(rlen >= 32);

    v = BE64(a->data[3]); memcpy(&r[0], &v, sizeof(v));
    v = BE64(a->data[2]); memcpy(&r[8], &v, sizeof(v));
    v = BE64(a->data[1]); memcpy(&r[16], &v, sizeof(v));
    v = BE64(a->data[0]); memcpy(&r[24], &v, sizeof(v));
}

static void secp256k1_num_set_bin(secp256k1_num *r, const unsigned char *a, unsigned int alen) {
    uint64_t v;
    (void) alen;
    VERIFY_CHECK(alen >= 32);

    r->data[4] = 0;
    memcpy(&v, &a[0], sizeof(v)); r->data[3] = BE64(v);
    memcpy(&v, &a[8], sizeof(v)); r->data[2] = BE64(v);
    memcpy(&v, &a[16], sizeof(v)); r->data[1] = BE64(v);
    memcpy(&v, &a[24], sizeof(v)); r->data[0] = BE64(v);
}

#endif
