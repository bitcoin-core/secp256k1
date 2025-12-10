/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_HASH_IMPL_H
#define SECP256K1_HASH_IMPL_H

#include "hash.h"
#include "util.h"

#include "../include/secp256k1_sha.h"

#include <stdlib.h>
#include <stdint.h>
#include <string.h>

static void secp256k1_sha256_initialize(secp256k1_sha256 *hash, sha256_transform_callback fn_transform) {
    hash->s[0] = 0x6a09e667ul;
    hash->s[1] = 0xbb67ae85ul;
    hash->s[2] = 0x3c6ef372ul;
    hash->s[3] = 0xa54ff53aul;
    hash->s[4] = 0x510e527ful;
    hash->s[5] = 0x9b05688cul;
    hash->s[6] = 0x1f83d9abul;
    hash->s[7] = 0x5be0cd19ul;
    hash->bytes = 0;
    hash->fn_transform = fn_transform == NULL ? secp256k1_sha256_transform : fn_transform;
}

static void secp256k1_sha256_write(secp256k1_sha256 *hash, const unsigned char *data, size_t len) {
    size_t bufsize = hash->bytes & 0x3F;
    hash->bytes += len;
    VERIFY_CHECK(hash->bytes >= len);
    while (len >= 64 - bufsize) {
        /* Fill the buffer, and process it. */
        size_t chunk_len = 64 - bufsize;
        memcpy(hash->buf + bufsize, data, chunk_len);
        data += chunk_len;
        len -= chunk_len;
        hash->fn_transform(hash->s, hash->buf, 1);
        bufsize = 0;
    }
    if (len) {
        /* Fill the buffer with what remains. */
        memcpy(hash->buf + bufsize, data, len);
    }
}

static void secp256k1_sha256_finalize(secp256k1_sha256 *hash, unsigned char *out32) {
    static const unsigned char pad[64] = {0x80};
    unsigned char sizedesc[8];
    int i;
    /* The maximum message size of SHA256 is 2^64-1 bits. */
    VERIFY_CHECK(hash->bytes < ((uint64_t)1 << 61));
    secp256k1_write_be32(&sizedesc[0], hash->bytes >> 29);
    secp256k1_write_be32(&sizedesc[4], hash->bytes << 3);
    secp256k1_sha256_write(hash, pad, 1 + ((119 - (hash->bytes % 64)) % 64));
    secp256k1_sha256_write(hash, sizedesc, 8);
    for (i = 0; i < 8; i++) {
        secp256k1_write_be32(&out32[4*i], hash->s[i]);
        hash->s[i] = 0;
    }
}

static int secp256k1_sha256_check_transform(sha256_transform_callback fn_transform) {
    secp256k1_sha256 sha256;
    unsigned char out[2][32];

    /* Four messages of different sizes: 1, 24, 64 and 81 bytes */
    unsigned char* msgs[4];
    size_t lens[4];
    unsigned char msg_0 = 0;
    unsigned char msg_1[24] = "secp256k1_verif_round_i";
    unsigned char msg_2[64] = "For this test, this 63-byte string will be used as input data i";
    unsigned char msg_3[81] = "Genesis: The Times 03/Jan/2009 Chancellor on brink of second bailout for banks i";
    msgs[0] = &msg_0;  lens[0] = sizeof(msg_0);
    msgs[1] = msg_1;   lens[1] = sizeof(msg_1);
    msgs[2] = msg_2;   lens[2] = sizeof(msg_2);
    msgs[3] = msg_3;   lens[3] = sizeof(msg_3);

    /* Compare hashes between built-in transform vs the one provided by the user */
    {
        unsigned char i, j, k;
        sha256_transform_callback funcs[2];
        funcs[0] = secp256k1_sha256_transform; /* Built-in */
        funcs[1] = fn_transform;               /* User provided */

        for (i = 0; i < 10; i++) {
            msg_0 = i;
            msg_1[23] = i;
            msg_2[63] = i;
            msg_3[80] = i;
            for (j = 0; j < 4; j++) {
                for (k = 0; k < 2; k++) {
                    secp256k1_sha256_initialize(&sha256, funcs[k]);
                    secp256k1_sha256_write(&sha256, msgs[j], lens[j]);
                    secp256k1_sha256_finalize(&sha256, out[k]);
                }
                if (memcmp(out[0], out[1], 32) != 0) return 0;
            }
        }
    }
    return 1;
}

/* Initializes a sha256 struct and writes the 64 byte string
 * SHA256(tag)||SHA256(tag) into it. */
static void secp256k1_sha256_initialize_tagged(secp256k1_sha256 *hash, const unsigned char *tag, size_t taglen, sha256_transform_callback fn_sha256_transform) {
    unsigned char buf[32];
    secp256k1_sha256_initialize(hash, fn_sha256_transform);
    secp256k1_sha256_write(hash, tag, taglen);
    secp256k1_sha256_finalize(hash, buf);

    secp256k1_sha256_initialize(hash, fn_sha256_transform);
    secp256k1_sha256_write(hash, buf, 32);
    secp256k1_sha256_write(hash, buf, 32);
}

static void secp256k1_sha256_clear(secp256k1_sha256 *hash) {
    secp256k1_memclear_explicit(hash, sizeof(*hash));
}

static void secp256k1_hmac_sha256_initialize(secp256k1_hmac_sha256 *hash, const unsigned char *key, size_t keylen, sha256_transform_callback fn_sha256_transform) {
    size_t n;
    unsigned char rkey[64];
    if (keylen <= sizeof(rkey)) {
        memcpy(rkey, key, keylen);
        memset(rkey + keylen, 0, sizeof(rkey) - keylen);
    } else {
        secp256k1_sha256 sha256;
        secp256k1_sha256_initialize(&sha256, fn_sha256_transform);
        secp256k1_sha256_write(&sha256, key, keylen);
        secp256k1_sha256_finalize(&sha256, rkey);
        memset(rkey + 32, 0, 32);
    }

    secp256k1_sha256_initialize(&hash->outer, fn_sha256_transform);
    for (n = 0; n < sizeof(rkey); n++) {
        rkey[n] ^= 0x5c;
    }
    secp256k1_sha256_write(&hash->outer, rkey, sizeof(rkey));

    secp256k1_sha256_initialize(&hash->inner, fn_sha256_transform);
    for (n = 0; n < sizeof(rkey); n++) {
        rkey[n] ^= 0x5c ^ 0x36;
    }
    secp256k1_sha256_write(&hash->inner, rkey, sizeof(rkey));
    secp256k1_memclear_explicit(rkey, sizeof(rkey));
}

static void secp256k1_hmac_sha256_write(secp256k1_hmac_sha256 *hash, const unsigned char *data, size_t size) {
    secp256k1_sha256_write(&hash->inner, data, size);
}

static void secp256k1_hmac_sha256_finalize(secp256k1_hmac_sha256 *hash, unsigned char *out32) {
    unsigned char temp[32];
    secp256k1_sha256_finalize(&hash->inner, temp);
    secp256k1_sha256_write(&hash->outer, temp, 32);
    secp256k1_memclear_explicit(temp, sizeof(temp));
    secp256k1_sha256_finalize(&hash->outer, out32);
}

static void secp256k1_hmac_sha256_clear(secp256k1_hmac_sha256 *hash) {
    secp256k1_memclear_explicit(hash, sizeof(*hash));
}

static void secp256k1_rfc6979_hmac_sha256_initialize(secp256k1_rfc6979_hmac_sha256 *rng, const unsigned char *key, size_t keylen, sha256_transform_callback fn_sha256_transform) {
    secp256k1_hmac_sha256 hmac;
    static const unsigned char zero[1] = {0x00};
    static const unsigned char one[1] = {0x01};

    memset(rng->v, 0x01, 32); /* RFC6979 3.2.b. */
    memset(rng->k, 0x00, 32); /* RFC6979 3.2.c. */

    /* RFC6979 3.2.d. */
    secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32, fn_sha256_transform);
    secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
    secp256k1_hmac_sha256_write(&hmac, zero, 1);
    secp256k1_hmac_sha256_write(&hmac, key, keylen);
    secp256k1_hmac_sha256_finalize(&hmac, rng->k);
    secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32, fn_sha256_transform);
    secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
    secp256k1_hmac_sha256_finalize(&hmac, rng->v);

    /* RFC6979 3.2.f. */
    secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32, fn_sha256_transform);
    secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
    secp256k1_hmac_sha256_write(&hmac, one, 1);
    secp256k1_hmac_sha256_write(&hmac, key, keylen);
    secp256k1_hmac_sha256_finalize(&hmac, rng->k);
    secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32, fn_sha256_transform);
    secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
    secp256k1_hmac_sha256_finalize(&hmac, rng->v);
    rng->retry = 0;
}

static void secp256k1_rfc6979_hmac_sha256_generate(secp256k1_rfc6979_hmac_sha256 *rng, unsigned char *out, size_t outlen, sha256_transform_callback fn_sha256_transform) {
    /* RFC6979 3.2.h. */
    static const unsigned char zero[1] = {0x00};
    if (rng->retry) {
        secp256k1_hmac_sha256 hmac;
        secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32, fn_sha256_transform);
        secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
        secp256k1_hmac_sha256_write(&hmac, zero, 1);
        secp256k1_hmac_sha256_finalize(&hmac, rng->k);
        secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32, fn_sha256_transform);
        secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
        secp256k1_hmac_sha256_finalize(&hmac, rng->v);
    }

    while (outlen > 0) {
        secp256k1_hmac_sha256 hmac;
        size_t now = outlen;
        secp256k1_hmac_sha256_initialize(&hmac, rng->k, 32, fn_sha256_transform);
        secp256k1_hmac_sha256_write(&hmac, rng->v, 32);
        secp256k1_hmac_sha256_finalize(&hmac, rng->v);
        if (now > 32) {
            now = 32;
        }
        memcpy(out, rng->v, now);
        out += now;
        outlen -= now;
    }

    rng->retry = 1;
}

static void secp256k1_rfc6979_hmac_sha256_finalize(secp256k1_rfc6979_hmac_sha256 *rng) {
    (void) rng;
}

static void secp256k1_rfc6979_hmac_sha256_clear(secp256k1_rfc6979_hmac_sha256 *rng) {
    secp256k1_memclear_explicit(rng, sizeof(*rng));
}

#endif /* SECP256K1_HASH_IMPL_H */
