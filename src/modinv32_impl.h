/***********************************************************************
 * Copyright (c) 2020 Peter Dettman                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef SECP256K1_MODINV32_IMPL_H
#define SECP256K1_MODINV32_IMPL_H

#include "modinv32.h"

#include "util.h"

static void secp256k1_modinv32_normalize_30(secp256k1_modinv32_signed30 *r, int32_t sign, const secp256k1_modinv32_modinfo *modinfo) {
    const int32_t M30 = (int32_t)(UINT32_MAX >> 2);
    int32_t r0 = r->v[0], r1 = r->v[1], r2 = r->v[2], r3 = r->v[3], r4 = r->v[4],
            r5 = r->v[5], r6 = r->v[6], r7 = r->v[7], r8 = r->v[8];
    int32_t cond_add, cond_negate;

    cond_add = r8 >> 31;

    r0 += modinfo->modulus.v[0] & cond_add;
    r1 += modinfo->modulus.v[1] & cond_add;
    r2 += modinfo->modulus.v[2] & cond_add;
    r3 += modinfo->modulus.v[3] & cond_add;
    r4 += modinfo->modulus.v[4] & cond_add;
    r5 += modinfo->modulus.v[5] & cond_add;
    r6 += modinfo->modulus.v[6] & cond_add;
    r7 += modinfo->modulus.v[7] & cond_add;
    r8 += modinfo->modulus.v[8] & cond_add;

    cond_negate = sign >> 31;

    r0 = (r0 ^ cond_negate) - cond_negate;
    r1 = (r1 ^ cond_negate) - cond_negate;
    r2 = (r2 ^ cond_negate) - cond_negate;
    r3 = (r3 ^ cond_negate) - cond_negate;
    r4 = (r4 ^ cond_negate) - cond_negate;
    r5 = (r5 ^ cond_negate) - cond_negate;
    r6 = (r6 ^ cond_negate) - cond_negate;
    r7 = (r7 ^ cond_negate) - cond_negate;
    r8 = (r8 ^ cond_negate) - cond_negate;

    r1 += r0 >> 30; r0 &= M30;
    r2 += r1 >> 30; r1 &= M30;
    r3 += r2 >> 30; r2 &= M30;
    r4 += r3 >> 30; r3 &= M30;
    r5 += r4 >> 30; r4 &= M30;
    r6 += r5 >> 30; r5 &= M30;
    r7 += r6 >> 30; r6 &= M30;
    r8 += r7 >> 30; r7 &= M30;

    cond_add = r8 >> 31;

    r0 += modinfo->modulus.v[0] & cond_add;
    r1 += modinfo->modulus.v[1] & cond_add;
    r2 += modinfo->modulus.v[2] & cond_add;
    r3 += modinfo->modulus.v[3] & cond_add;
    r4 += modinfo->modulus.v[4] & cond_add;
    r5 += modinfo->modulus.v[5] & cond_add;
    r6 += modinfo->modulus.v[6] & cond_add;
    r7 += modinfo->modulus.v[7] & cond_add;
    r8 += modinfo->modulus.v[8] & cond_add;

    r1 += r0 >> 30; r0 &= M30;
    r2 += r1 >> 30; r1 &= M30;
    r3 += r2 >> 30; r2 &= M30;
    r4 += r3 >> 30; r3 &= M30;
    r5 += r4 >> 30; r4 &= M30;
    r6 += r5 >> 30; r5 &= M30;
    r7 += r6 >> 30; r6 &= M30;
    r8 += r7 >> 30; r7 &= M30;

    r->v[0] = r0;
    r->v[1] = r1;
    r->v[2] = r2;
    r->v[3] = r3;
    r->v[4] = r4;
    r->v[5] = r5;
    r->v[6] = r6;
    r->v[7] = r7;
    r->v[8] = r8;
}

typedef struct {
    int32_t u, v, q, r;
} secp256k1_modinv32_trans2x2;

static int32_t secp256k1_modinv32_divsteps_30(int32_t eta, uint32_t f0, uint32_t g0, secp256k1_modinv32_trans2x2 *t) {
    uint32_t u = 1, v = 0, q = 0, r = 1;
    uint32_t c1, c2, f = f0, g = g0, x, y, z;
    int i;

    for (i = 0; i < 30; ++i) {
        VERIFY_CHECK((f & 1) == 1);
        VERIFY_CHECK((u * f0 + v * g0) == f << i);
        VERIFY_CHECK((q * f0 + r * g0) == g << i);

        c1 = eta >> 31;
        c2 = -(g & 1);

        x = (f ^ c1) - c1;
        y = (u ^ c1) - c1;
        z = (v ^ c1) - c1;

        g += x & c2;
        q += y & c2;
        r += z & c2;

        c1 &= c2;
        eta = (eta ^ c1) - (c1 + 1);

        f += g & c1;
        u += q & c1;
        v += r & c1;

        g >>= 1;
        u <<= 1;
        v <<= 1;
    }

    t->u = (int32_t)u;
    t->v = (int32_t)v;
    t->q = (int32_t)q;
    t->r = (int32_t)r;

    return eta;
}

static int32_t secp256k1_modinv32_divsteps_30_var(int32_t eta, uint32_t f0, uint32_t g0, secp256k1_modinv32_trans2x2 *t) {
    /* inv256[i] = -(2*i+1)^-1 (mod 256) */
    static const uint8_t inv256[128] = {
        0xFF, 0x55, 0x33, 0x49, 0xC7, 0x5D, 0x3B, 0x11, 0x0F, 0xE5, 0xC3, 0x59,
        0xD7, 0xED, 0xCB, 0x21, 0x1F, 0x75, 0x53, 0x69, 0xE7, 0x7D, 0x5B, 0x31,
        0x2F, 0x05, 0xE3, 0x79, 0xF7, 0x0D, 0xEB, 0x41, 0x3F, 0x95, 0x73, 0x89,
        0x07, 0x9D, 0x7B, 0x51, 0x4F, 0x25, 0x03, 0x99, 0x17, 0x2D, 0x0B, 0x61,
        0x5F, 0xB5, 0x93, 0xA9, 0x27, 0xBD, 0x9B, 0x71, 0x6F, 0x45, 0x23, 0xB9,
        0x37, 0x4D, 0x2B, 0x81, 0x7F, 0xD5, 0xB3, 0xC9, 0x47, 0xDD, 0xBB, 0x91,
        0x8F, 0x65, 0x43, 0xD9, 0x57, 0x6D, 0x4B, 0xA1, 0x9F, 0xF5, 0xD3, 0xE9,
        0x67, 0xFD, 0xDB, 0xB1, 0xAF, 0x85, 0x63, 0xF9, 0x77, 0x8D, 0x6B, 0xC1,
        0xBF, 0x15, 0xF3, 0x09, 0x87, 0x1D, 0xFB, 0xD1, 0xCF, 0xA5, 0x83, 0x19,
        0x97, 0xAD, 0x8B, 0xE1, 0xDF, 0x35, 0x13, 0x29, 0xA7, 0x3D, 0x1B, 0xF1,
        0xEF, 0xC5, 0xA3, 0x39, 0xB7, 0xCD, 0xAB, 0x01
    };

    uint32_t u = 1, v = 0, q = 0, r = 1;
    uint32_t f = f0, g = g0, m;
    uint16_t w;
    int i = 30, limit, zeros;

    for (;;) {
        /* Use a sentinel bit to count zeros only up to i. */
        zeros = secp256k1_ctz32_var(g | (UINT32_MAX << i));

        g >>= zeros;
        u <<= zeros;
        v <<= zeros;
        eta -= zeros;
        i -= zeros;

        if (i <= 0) {
            break;
        }

        VERIFY_CHECK((f & 1) == 1);
        VERIFY_CHECK((g & 1) == 1);
        VERIFY_CHECK((u * f0 + v * g0) == f << (30 - i));
        VERIFY_CHECK((q * f0 + r * g0) == g << (30 - i));

        if (eta < 0) {
            uint32_t tmp;
            eta = -eta;
            tmp = f; f = g; g = -tmp;
            tmp = u; u = q; q = -tmp;
            tmp = v; v = r; r = -tmp;
        }

        /* Handle up to 8 divsteps at once, subject to eta and i. */
        limit = ((int)eta + 1) > i ? i : ((int)eta + 1);
        m = (UINT32_MAX >> (32 - limit)) & 255U;

        w = (g * inv256[(f >> 1) & 127]) & m;

        g += f * w;
        q += u * w;
        r += v * w;

        VERIFY_CHECK((g & m) == 0);
    }

    t->u = (int32_t)u;
    t->v = (int32_t)v;
    t->q = (int32_t)q;
    t->r = (int32_t)r;

    return eta;
}

static void secp256k1_modinv32_update_de_30(secp256k1_modinv32_signed30 *d, secp256k1_modinv32_signed30 *e, const secp256k1_modinv32_trans2x2 *t, const secp256k1_modinv32_modinfo* modinfo) {
    const int32_t M30 = (int32_t)(UINT32_MAX >> 2);
    const int32_t u = t->u, v = t->v, q = t->q, r = t->r;
    int32_t di, ei, md, me, sd, se;
    int64_t cd, ce;
    int i;

    /*
     * On input, d/e must be in the range (-2.P, P). For initially negative d (resp. e), we add
     * u and/or v (resp. q and/or r) multiples of the modulus to the corresponding output (prior
     * to division by 2^30). This has the same effect as if we added the modulus to the input(s).
     */

    sd = d->v[8] >> 31;
    se = e->v[8] >> 31;

    md = (u & sd) + (v & se);
    me = (q & sd) + (r & se);

    di = d->v[0];
    ei = e->v[0];

    cd = (int64_t)u * di + (int64_t)v * ei;
    ce = (int64_t)q * di + (int64_t)r * ei;

    /*
     * Subtract from md/me an extra term in the range [0, 2^30) such that the low 30 bits of each
     * sum of products will be 0. This allows clean division by 2^30. On output, d/e are thus in
     * the range (-2.P, P), consistent with the input constraint.
     */

    md -= (modinfo->modulus_inv30 * (uint32_t)cd + md) & M30;
    me -= (modinfo->modulus_inv30 * (uint32_t)ce + me) & M30;

    cd += (int64_t)modinfo->modulus.v[0] * md;
    ce += (int64_t)modinfo->modulus.v[0] * me;

    VERIFY_CHECK(((int32_t)cd & M30) == 0); cd >>= 30;
    VERIFY_CHECK(((int32_t)ce & M30) == 0); ce >>= 30;

    for (i = 1; i < 9; ++i) {
        di = d->v[i];
        ei = e->v[i];

        cd += (int64_t)u * di + (int64_t)v * ei;
        ce += (int64_t)q * di + (int64_t)r * ei;

        cd += (int64_t)modinfo->modulus.v[i] * md;
        ce += (int64_t)modinfo->modulus.v[i] * me;

        d->v[i - 1] = (int32_t)cd & M30; cd >>= 30;
        e->v[i - 1] = (int32_t)ce & M30; ce >>= 30;
    }

    d->v[8] = (int32_t)cd;
    e->v[8] = (int32_t)ce;
}

static void secp256k1_modinv32_update_fg_30(secp256k1_modinv32_signed30 *f, secp256k1_modinv32_signed30 *g, const secp256k1_modinv32_trans2x2 *t) {
    const int32_t M30 = (int32_t)(UINT32_MAX >> 2);
    const int32_t u = t->u, v = t->v, q = t->q, r = t->r;
    int32_t fi, gi;
    int64_t cf, cg;
    int i;

    fi = f->v[0];
    gi = g->v[0];

    cf = (int64_t)u * fi + (int64_t)v * gi;
    cg = (int64_t)q * fi + (int64_t)r * gi;

    VERIFY_CHECK(((int32_t)cf & M30) == 0);
    VERIFY_CHECK(((int32_t)cg & M30) == 0);

    cf >>= 30;
    cg >>= 30;

    for (i = 1; i < 9; ++i) {
        fi = f->v[i];
        gi = g->v[i];

        cf += (int64_t)u * fi + (int64_t)v * gi;
        cg += (int64_t)q * fi + (int64_t)r * gi;

        f->v[i - 1] = (int32_t)cf & M30; cf >>= 30;
        g->v[i - 1] = (int32_t)cg & M30; cg >>= 30;
    }

    f->v[8] = (int32_t)cf;
    g->v[8] = (int32_t)cg;
}

static void secp256k1_modinv32(secp256k1_modinv32_signed30 *x, const secp256k1_modinv32_modinfo *modinfo) {
    /* Modular inversion based on the paper "Fast constant-time gcd computation and
     * modular inversion" by Daniel J. Bernstein and Bo-Yin Yang. */
    secp256k1_modinv32_signed30 d = {{0}};
    secp256k1_modinv32_signed30 e = {{1}};
    secp256k1_modinv32_signed30 f = modinfo->modulus;
    secp256k1_modinv32_signed30 g = *x;
    int i;
    int32_t eta;

    /* The paper uses 'delta'; eta == -delta (a performance tweak).
     *
     * If the maximum bitlength of g is known to be less than 256, then eta can be set
     * initially to -(1 + (256 - maxlen(g))), and only (741 - (256 - maxlen(g))) total
     * divsteps are needed. */
    eta = -1;

    for (i = 0; i < 25; ++i) {
        secp256k1_modinv32_trans2x2 t;
        eta = secp256k1_modinv32_divsteps_30(eta, f.v[0], g.v[0], &t);
        secp256k1_modinv32_update_de_30(&d, &e, &t, modinfo);
        secp256k1_modinv32_update_fg_30(&f, &g, &t);
    }

    /* At this point sufficient iterations have been performed that g must have reached 0
     * and (if g was not originally 0) f must now equal +/- GCD of the initial f, g
     * values i.e. +/- 1, and d now contains +/- the modular inverse. */
    VERIFY_CHECK((g.v[0] | g.v[1] | g.v[2] | g.v[3] | g.v[4] | g.v[5] | g.v[6] | g.v[7] | g.v[8]) == 0);

    secp256k1_modinv32_normalize_30(&d, f.v[8] >> 31, modinfo);

    *x = d;
}

static void secp256k1_modinv32_var(secp256k1_modinv32_signed30 *x, const secp256k1_modinv32_modinfo *modinfo) {
    /* Modular inversion based on the paper "Fast constant-time gcd computation and
     * modular inversion" by Daniel J. Bernstein and Bo-Yin Yang. */
    secp256k1_modinv32_signed30 d = {{0, 0, 0, 0, 0, 0, 0, 0, 0}};
    secp256k1_modinv32_signed30 e = {{1, 0, 0, 0, 0, 0, 0, 0, 0}};
    secp256k1_modinv32_signed30 f = modinfo->modulus;
    secp256k1_modinv32_signed30 g = *x;
    int j;
    int32_t eta;
    int32_t cond;

    /* The paper uses 'delta'; eta == -delta (a performance tweak).
     *
     * If g has leading zeros (w.r.t 256 bits), then eta can be set initially to
     * -(1 + clz(g)), and the worst-case divstep count would be only (741 - clz(g)). */
    eta = -1;

    while (1) {
        secp256k1_modinv32_trans2x2 t;
        eta = secp256k1_modinv32_divsteps_30_var(eta, f.v[0], g.v[0], &t);
        secp256k1_modinv32_update_de_30(&d, &e, &t, modinfo);
        secp256k1_modinv32_update_fg_30(&f, &g, &t);
        if (g.v[0] == 0) {
            cond = 0;
            for (j = 1; j < 9; ++j) {
                cond |= g.v[j];
            }
            if (cond == 0) break;
        }
    }

    /* At this point g is 0 and (if g was not originally 0) f must now equal +/- GCD of
     * the initial f, g values i.e. +/- 1, and d now contains +/- the modular inverse. */

    secp256k1_modinv32_normalize_30(&d, f.v[8] >> 31, modinfo);

    *x = d;
}

#endif /* SECP256K1_MODINV32_IMPL_H */
