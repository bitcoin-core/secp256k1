/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_HAZMAT_MAIN_H
#define SECP256K1_MODULE_HAZMAT_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_hazmat.h"
#include "../../scalar.h"
#include "../../group.h"
#include "../../eckey.h"
#include "../../ecmult_const.h"

typedef struct {
    secp256k1_gej gej;
    int z_is_one; /* set if z == 1, i.e. gej can be converted to ge trivially by assigning x/y */
} secp256k1_hazmat_point_struct;

/* Verify that the opaque data types are large enough to hold the underlying structures
   (note that this function is never called at run-time and only exists since the STATIC_ASSERT
    macro can only be used inside of functions) */
static void secp256k1_hazmat_assertions(void) {
    STATIC_ASSERT(sizeof(secp256k1_hazmat_scalar) >= sizeof(secp256k1_scalar));
    STATIC_ASSERT(sizeof(secp256k1_hazmat_point)  >= sizeof(secp256k1_hazmat_point_struct));
}

int secp256k1_hazmat_scalar_parse(secp256k1_hazmat_scalar *s, const unsigned char *bin32) {
    int overflow;
    secp256k1_scalar_set_b32((secp256k1_scalar*)s, bin32, &overflow);
    return !overflow;
}

void secp256k1_hazmat_scalar_serialize(unsigned char *bin32, const secp256k1_hazmat_scalar *s) {
    secp256k1_scalar_get_b32(bin32, (secp256k1_scalar*)s);
}

void secp256k1_hazmat_scalar_set_zero(secp256k1_hazmat_scalar *s) {
    *((secp256k1_scalar*)s) = secp256k1_scalar_zero;
}

int secp256k1_hazmat_scalar_is_zero(const secp256k1_hazmat_scalar *s) {
    return secp256k1_scalar_is_zero((secp256k1_scalar*)s);
}

void secp256k1_hazmat_scalar_add(secp256k1_hazmat_scalar *sres, const secp256k1_hazmat_scalar *s1, const secp256k1_hazmat_scalar *s2) {
    secp256k1_scalar_add((secp256k1_scalar*)sres, (secp256k1_scalar*)s1, (secp256k1_scalar*)s2);
}

void secp256k1_hazmat_scalar_mul(secp256k1_hazmat_scalar *sres, const secp256k1_hazmat_scalar *s1, const secp256k1_hazmat_scalar *s2) {
    secp256k1_scalar_mul((secp256k1_scalar*)sres, (secp256k1_scalar*)s1, (secp256k1_scalar*)s2);
}

void secp256k1_hazmat_scalar_negate(secp256k1_hazmat_scalar *s) {
    secp256k1_scalar_negate((secp256k1_scalar*)s, (secp256k1_scalar*)s);
}

static void secp256k1_hazmat_point_to_ge(secp256k1_ge *ge, secp256k1_hazmat_point_struct *p) {
    if (p->z_is_one) {
        secp256k1_ge_set_xy(ge, &p->gej.x, &p->gej.y);
    } else {
        secp256k1_ge_set_gej(ge, &p->gej);
        p->z_is_one = 1;
    }
}

int secp256k1_hazmat_point_parse(secp256k1_hazmat_point *p, const unsigned char *pubkey33) {
    secp256k1_hazmat_point_struct *ps = (secp256k1_hazmat_point_struct*)p;
    secp256k1_ge ge;

    if (!secp256k1_eckey_pubkey_parse(&ge, pubkey33, 33)) {
        return 0;
    }
    secp256k1_gej_set_ge(&ps->gej, &ge);
    ps->z_is_one = 1;
    return 1;
}

void secp256k1_hazmat_point_serialize(unsigned char *pubkey33, secp256k1_hazmat_point *p) {
    secp256k1_hazmat_point_struct *ps = (secp256k1_hazmat_point_struct*)p;
    secp256k1_ge ge;
    size_t size;
    int ret;

    secp256k1_hazmat_point_to_ge(&ge, ps);
    ret = secp256k1_eckey_pubkey_serialize(&ge, pubkey33, &size, 1);
    VERIFY_CHECK(ret == 1 && size == 33);
    (void)ret;
}

void secp256k1_hazmat_point_set_infinity(secp256k1_hazmat_point *p) {
    secp256k1_hazmat_point_struct *ps = (secp256k1_hazmat_point_struct*)p;

    secp256k1_gej_set_infinity(&ps->gej);
    ps->z_is_one = 0;
}

int secp256k1_hazmat_point_is_infinity(const secp256k1_hazmat_point *p) {
    const secp256k1_hazmat_point_struct *ps = (const secp256k1_hazmat_point_struct*)p;

    return secp256k1_gej_is_infinity(&ps->gej);
}

void secp256k1_hazmat_point_add(secp256k1_hazmat_point *pres, secp256k1_hazmat_point *p1, secp256k1_hazmat_point *p2) {
    secp256k1_hazmat_point_struct *press = (secp256k1_hazmat_point_struct*)pres;
    secp256k1_hazmat_point_struct *p1s = (secp256k1_hazmat_point_struct*)p1;
    secp256k1_hazmat_point_struct *p2s = (secp256k1_hazmat_point_struct*)p2;
    secp256k1_ge ge;

    secp256k1_hazmat_point_to_ge(&ge, p2s);
    secp256k1_gej_add_ge(&press->gej, &p1s->gej, &ge);
    press->z_is_one = 0;
}

void secp256k1_hazmat_point_negate(secp256k1_hazmat_point *p) {
    secp256k1_hazmat_point_struct *ps = (secp256k1_hazmat_point_struct*)p;

    secp256k1_gej_neg(&ps->gej, &ps->gej);
    /* negation only changes y; z is untouched, so no update of z_is_one is needed */
}

int secp256k1_hazmat_point_equal(const secp256k1_hazmat_point *p1, const secp256k1_hazmat_point *p2) {
    const secp256k1_hazmat_point_struct *p1s = (secp256k1_hazmat_point_struct*)p1;
    const secp256k1_hazmat_point_struct *p2s = (secp256k1_hazmat_point_struct*)p2;

    return secp256k1_gej_eq_var(&p1s->gej, &p2s->gej);
}

void secp256k1_hazmat_multiply_with_generator(const secp256k1_context *ctx, secp256k1_hazmat_point *p, const secp256k1_hazmat_scalar *s) {
    secp256k1_hazmat_point_struct *ps = (secp256k1_hazmat_point_struct*)p;

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &ps->gej, (secp256k1_scalar*)s);
    ps->z_is_one = 0;
}

void secp256k1_hazmat_multiply_with_point(secp256k1_hazmat_point *pres, const secp256k1_hazmat_scalar *s, secp256k1_hazmat_point *p) {
    secp256k1_hazmat_point_struct *press = (secp256k1_hazmat_point_struct*)pres;
    secp256k1_hazmat_point_struct *ps = (secp256k1_hazmat_point_struct*)p;
    secp256k1_ge ge;

    secp256k1_hazmat_point_to_ge(&ge, ps);
    secp256k1_ecmult_const(&press->gej, &ge, (secp256k1_scalar*)s);
    press->z_is_one = 0;
}

#endif
