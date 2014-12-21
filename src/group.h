/**********************************************************************
 * Copyright (c) 2013, 2014 Pieter Wuille                             *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_GROUP_
#define _SECP256K1_GROUP_

#include "num.h"
#include "field.h"

/** A group element of the secp256k1 curve, in affine coordinates. */
typedef struct {
    secp256k1_fe_t x;
    secp256k1_fe_t y;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_ge_t;

/** A group element of the secp256k1 curve, in jacobian coordinates. */
typedef struct {
    secp256k1_fe_t x; /* actual X: x/z^2 */
    secp256k1_fe_t y; /* actual Y: y/z^3 */
    secp256k1_fe_t z;
    int infinity; /* whether this represents the point at infinity */
} secp256k1_gej_t;

/** A group element of the secp256k1 curve, with an implicit z coordinate (and infinity flag).
 *  An instance of secp256k1_coz_t is always "co-z" with some instance of secp256k1_gej_t, from
 *  which it inherits its implied z coordinate and infinity flag. */
typedef struct {
    secp256k1_fe_t x; // actual X: x/z^2 (z implied)
    secp256k1_fe_t y; // actual Y: y/z^3 (z implied)
} secp256k1_coz_t;

/** Global constants related to the group */
typedef struct {
    secp256k1_ge_t g; /* the generator point */

#ifdef USE_ENDOMORPHISM
    /* constants related to secp256k1's efficiently computable endomorphism */
    secp256k1_fe_t beta;
#endif
} secp256k1_ge_consts_t;

static const secp256k1_ge_consts_t *secp256k1_ge_consts = NULL;

/** Initialize the group module. */
static void secp256k1_ge_start(void);

/** De-initialize the group module. */
static void secp256k1_ge_stop(void);

/** Set a group element equal to the point at infinity */
static void secp256k1_ge_set_infinity(secp256k1_ge_t *r);

/** Set a group element equal to the point with given X and Y coordinates */
static void secp256k1_ge_set_xy(secp256k1_ge_t *r, const secp256k1_fe_t *x, const secp256k1_fe_t *y);

/** Set a group element (affine) equal to the point with the given X coordinate, and given oddness
 *  for Y. Return value indicates whether the result is valid. */
static int secp256k1_ge_set_xo_var(secp256k1_ge_t *r, const secp256k1_fe_t *x, int odd);

/** Check whether a group element is the point at infinity. */
static int secp256k1_ge_is_infinity(const secp256k1_ge_t *a);

/** Check whether a group element is valid (i.e., on the curve). */
static int secp256k1_ge_is_valid_var(const secp256k1_ge_t *a);

static void secp256k1_ge_neg(secp256k1_ge_t *r, const secp256k1_ge_t *a);

/** Get a hex representation of a point. *rlen will be overwritten with the real length. */
static void secp256k1_ge_get_hex(char *r, int *rlen, const secp256k1_ge_t *a);

/** Set a group element equal to another which is given in jacobian coordinates */
static void secp256k1_ge_set_gej(secp256k1_ge_t *r, secp256k1_gej_t *a);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates */
static void secp256k1_ge_set_all_gej_var(size_t len, secp256k1_ge_t r[len], const secp256k1_gej_t a[len]);

/** Set a batch of group elements equal to the inputs given in jacobian coordinates (with known
 *  z-ratios). zr must contain the known z-ratios such that mul(a[i].z, zr[i]) == a[i+1].z, with
 *  mul(a[len-1].z, zr[len-1]) == 1 (i.e. the last zr element would normally be calculated by
 *  a field inversion of the last z element). */
static void secp256k1_ge_set_table_gej(size_t len, secp256k1_ge_t r[len], const secp256k1_gej_t a[len],
    const secp256k1_fe_t zr[len]);


/** Set a group element (jacobian) equal to the point at infinity. */
static void secp256k1_gej_set_infinity(secp256k1_gej_t *r);

/** Set a group element (jacobian) equal to the point with given X and Y coordinates. */
static void secp256k1_gej_set_xy(secp256k1_gej_t *r, const secp256k1_fe_t *x, const secp256k1_fe_t *y);

/** Set a group element (jacobian) equal to another which is given in affine coordinates. */
static void secp256k1_gej_set_ge(secp256k1_gej_t *r, const secp256k1_ge_t *a);

/** Compare the X coordinate of a group element (jacobian). */
static int secp256k1_gej_eq_x_var(const secp256k1_fe_t *x, const secp256k1_gej_t *a);

/** Set r equal to the inverse of a (i.e., mirrored around the X axis) */
static void secp256k1_gej_neg(secp256k1_gej_t *r, const secp256k1_gej_t *a);

/** Check whether a group element is the point at infinity. */
static int secp256k1_gej_is_infinity(const secp256k1_gej_t *a);

/** Set r equal to the double of a. */
static void secp256k1_gej_double_var(secp256k1_gej_t *r, const secp256k1_gej_t *a);

/** Set r equal to the sum of a and b. */
static void secp256k1_gej_add_var(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_gej_t *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates, and not infinity). */
static void secp256k1_gej_add_ge(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_ge_t *b);

/** Set r equal to the sum of a and b (with b given in affine coordinates). This is more efficient
    than secp256k1_gej_add_var. It is identical to secp256k1_gej_add_ge but without constant-time
    guarantee, and b is allowed to be infinity. */
static void secp256k1_gej_add_ge_var(secp256k1_gej_t *r, const secp256k1_gej_t *a, const secp256k1_fe_t *azr, const secp256k1_ge_t *b);

/** Get a hex representation of a point. *rlen will be overwritten with the real length. */
static void secp256k1_gej_get_hex(char *r, int *rlen, const secp256k1_gej_t *a);

#ifdef USE_ENDOMORPHISM
/** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
static void secp256k1_ge_mul_lambda(secp256k1_ge_t *r, const secp256k1_ge_t *a);

/** Set r to be equal to lambda times a, where lambda is chosen in a way such that this is very fast. */
static void secp256k1_gej_mul_lambda(secp256k1_gej_t *r, const secp256k1_gej_t *a);
#endif

/** Clear a secp256k1_gej_t to prevent leaking sensitive information. */
static void secp256k1_gej_clear(secp256k1_gej_t *r);

/** Clear a secp256k1_ge_t to prevent leaking sensitive information. */
static void secp256k1_ge_clear(secp256k1_ge_t *r);

/** Set r equal to the double of a, and ra equal to a, such that r is co-z with ra. */
static void secp256k1_coz_dblu_var(secp256k1_coz_t *r, secp256k1_gej_t *ra, const secp256k1_gej_t *a);

/** Set r equal to the sum of ra and b. ra is initially co-z with b and finally co-z with r. rzr
    returns the ratio r->z:b->z */
static void secp256k1_coz_zaddu_var(secp256k1_gej_t *r, secp256k1_coz_t *ra, secp256k1_fe_t *rzr,
    const secp256k1_gej_t *b);

#endif
