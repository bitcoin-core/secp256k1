/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_NUM_9X32_
#define _SECP256K1_NUM_9X32_

#include "util.h"

#define NUM_N_WORDS	9
#define NUM_WORD_WIDTH	32
#define NUM_WORD_CTLZ __builtin_clz
#define NUM_WORD_CTZ __builtin_ctz
typedef uint32_t secp256k1_num_word;
typedef int32_t secp256k1_num_sword;
typedef uint64_t secp256k1_num_dword;

typedef struct {
    /* we need an extra word for auxiallary stuff during algorithms,
     * so we have an extra word beyond what we need for 256-bit
     * numbers. Import/export (by set_bin and get_bin) expects to
     * work with 32-byte buffers, so the top word is not directly
     * accessible to users of the API. */
    secp256k1_num_word data[NUM_N_WORDS];
} secp256k1_num;

#endif
