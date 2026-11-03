/***********************************************************************
 * Copyright (c) 2020 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_SELFTEST_H
#define SECP256K1_SELFTEST_H

#include "hash.h"

static int secp256k1_selftest_passes(void) {
    /* Use default sha256 compression */
    return secp256k1_sha256_selftest(secp256k1_sha256_transform);
}

#endif /* SECP256K1_SELFTEST_H */
