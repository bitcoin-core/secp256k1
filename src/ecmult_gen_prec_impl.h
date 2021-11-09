/***********************************************************************
 * Copyright (c) 2013, 2014, 2015 Pieter Wuille, Gregory Maxwell       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_ECMULT_GEN_PREC_IMPL_H
#define SECP256K1_ECMULT_GEN_PREC_IMPL_H

#include "ecmult_gen_prec.h"
#include "group_impl.h"
#include "field_impl.h"
#include "ecmult_gen.h"

static void secp256k1_ecmult_gen_create_prec_table(secp256k1_ge_storage* table) {
    secp256k1_ge prec[ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G];
    secp256k1_gej gj;
    secp256k1_gej nums_gej;
    int i, j;

    /* get the generator */
    secp256k1_gej_set_ge(&gj, &secp256k1_ge_const_g);

    /* Construct a group element with no known corresponding scalar (nothing up my sleeve). */
    {
        static const unsigned char nums_b32[33] = "The scalar for this x is unknown";
        secp256k1_fe nums_x;
        secp256k1_ge nums_ge;
        int r;
        r = secp256k1_fe_set_b32(&nums_x, nums_b32);
        (void)r;
        VERIFY_CHECK(r);
        r = secp256k1_ge_set_xo_var(&nums_ge, &nums_x, 0);
        (void)r;
        VERIFY_CHECK(r);
        secp256k1_gej_set_ge(&nums_gej, &nums_ge);
        /* Add G to make the bits in x uniformly distributed. */
        secp256k1_gej_add_ge_var(&nums_gej, &nums_gej, &secp256k1_ge_const_g, NULL);
    }

    /* compute prec. */
    {
        secp256k1_gej precj[ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G]; /* Jacobian versions of prec. */
        secp256k1_gej gbase;
        secp256k1_gej numsbase;
        gbase = gj; /* PREC_G^j * G */
        numsbase = nums_gej; /* 2^j * nums. */
        for (j = 0; j < ECMULT_GEN_PREC_N; j++) {
            /* Set precj[j*PREC_G .. j*PREC_G+(PREC_G-1)] to (numsbase, numsbase + gbase, ..., numsbase + (PREC_G-1)*gbase). */
            precj[j*ECMULT_GEN_PREC_G] = numsbase;
            for (i = 1; i < ECMULT_GEN_PREC_G; i++) {
                secp256k1_gej_add_var(&precj[j*ECMULT_GEN_PREC_G + i], &precj[j*ECMULT_GEN_PREC_G + i - 1], &gbase, NULL);
            }
            /* Multiply gbase by PREC_G. */
            for (i = 0; i < ECMULT_GEN_PREC_B; i++) {
                secp256k1_gej_double_var(&gbase, &gbase, NULL);
            }
            /* Multiply numbase by 2. */
            secp256k1_gej_double_var(&numsbase, &numsbase, NULL);
            if (j == ECMULT_GEN_PREC_N - 2) {
                /* In the last iteration, numsbase is (1 - 2^j) * nums instead. */
                secp256k1_gej_neg(&numsbase, &numsbase);
                secp256k1_gej_add_var(&numsbase, &numsbase, &nums_gej, NULL);
            }
        }
        secp256k1_ge_set_all_gej_var(prec, precj, ECMULT_GEN_PREC_N * ECMULT_GEN_PREC_G);
    }
    for (j = 0; j < ECMULT_GEN_PREC_N; j++) {
        for (i = 0; i < ECMULT_GEN_PREC_G; i++) {
            secp256k1_ge_to_storage(&table[j*ECMULT_GEN_PREC_G + i], &prec[j*ECMULT_GEN_PREC_G + i]);
        }
    }
}

#endif /* SECP256K1_ECMULT_GEN_PREC_IMPL_H */
