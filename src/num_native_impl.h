/**********************************************************************
 * Copyright (c) 2015 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_NUM_NATIVE_IMPL_
#define _SECP256K1_NUM_NATIVE_IMPL_

/* secp256k1_num functions whose implementations are the same for both
 * 32- and 64-bit words. */

static void secp256k1_num_debug_print(const char *name, const secp256k1_num *a);

SECP256K1_INLINE static void secp256k1_num_copy(secp256k1_num *r, const secp256k1_num *a) {
    memcpy(r, a, sizeof(*a));
}

SECP256K1_INLINE static int secp256k1_num_cmp(const secp256k1_num *a, const secp256k1_num *b)
{
    int i;
    for (i = NUM_N_WORDS - 1; i >= 0; --i) {
        if (a->data[i] > b->data[i])
            return 1;
        else if (a->data[i] < b->data[i])
            return -1;
    }
    return 0;
}

SECP256K1_INLINE static int secp256k1_num_eq(const secp256k1_num *a, const secp256k1_num *b)
{
    int i;
    for (i = 0; i < NUM_N_WORDS; ++i)
        if (a->data[i] != b->data[i])
            return 0;
    return 1;
}

static void secp256k1_num_add(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b)
{
    unsigned carry = 0;
    int i;
    for (i = 0; i < NUM_N_WORDS; ++i) {
        unsigned carry1, carry2;
        secp256k1_num_word temp = a->data[i];
        r->data[i] = temp + b->data[i];
        carry1 = r->data[i] < temp;
        r->data[i] += carry;
        carry2 = r->data[i] < carry;
        carry = carry1 | carry2;
    }
}

/* this is a helper for div_mod; it left-shifts `b` by `shift` words before subtracting */
static void secp256k1_num_sub_shift_word(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b, int shift, int max) {
    unsigned borrow = 0;
    int i;
    for (i = shift; i < max; ++i) {
        unsigned borrow1, borrow2;
        secp256k1_num_word temp = a->data[i];
        r->data[i] = temp - b->data[i - shift];
        borrow1 = r->data[i] > temp;
        r->data[i] -= borrow;
        borrow2 = r->data[i] > (r->data[i] + borrow);
        borrow = borrow1 | borrow2;
    }
}

SECP256K1_INLINE static void secp256k1_num_sub(secp256k1_num *r, const secp256k1_num *a, const secp256k1_num *b) {
    secp256k1_num_sub_shift_word(r, a, b, 0, NUM_N_WORDS);
}

static void secp256k1_num_negate(secp256k1_num *r)
{
    int i;
    unsigned borrow = 0;
    for (i = 0; i < NUM_N_WORDS; ++i) {
        r->data[i] = -r->data[i] - borrow;
        borrow |= r->data[i] != 0;
    }
}

static void secp256k1_num_shift(secp256k1_num *r, int bits) {
    int s_word = bits / NUM_WORD_WIDTH;
    int s_bits = bits % NUM_WORD_WIDTH;
    int i;

    for (i = s_word; i < NUM_N_WORDS; ++i) {
        r->data[i - s_word] = r->data[i] >> s_bits;
        if (i < NUM_N_WORDS - 1 && s_bits > 0) {
            r->data[i - s_word] |= r->data[i + 1] << (NUM_WORD_WIDTH - s_bits);
        }
    }
    for (i = NUM_N_WORDS - s_word; i < NUM_N_WORDS; ++i)
        r->data[i] = 0;
}

SECP256K1_INLINE static int secp256k1_num_is_zero(const secp256k1_num *a) {
    int i;
    for (i = 0; i < NUM_N_WORDS - 1; ++i)
        if (a->data[i] != 0)
            return 0;
    return 1;
}

SECP256K1_INLINE static int secp256k1_num_is_neg(const secp256k1_num *a) {
    return a->data[NUM_N_WORDS - 1] >> (NUM_WORD_WIDTH - 1);
}

/* div_mod and helpers */
static void secp256k1_num_div_get_shifts(int *word_shift, int *bit_shift, const secp256k1_num *a) {
    int i;
    /* These defaults will never be used, since this function is never called with a == 0,
     * but we need them here to avoid gcc warnings about uninitialized variables. */
    *word_shift = NUM_N_WORDS;
    *bit_shift = 0;
    for (i = NUM_N_WORDS - 1; i >= 0; --i) {
        if (a->data[i] != 0) {
            *word_shift = NUM_N_WORDS - 1 - i;
            *bit_shift = NUM_WORD_CTLZ(a->data[i]);
            return;
        }
    }
    /* Only way to get here is if we were passed zero as divisor */
    VERIFY_CHECK(0);
}

static void secp256k1_num_div_mul_word(secp256k1_num *r, const secp256k1_num *a, secp256k1_num_word w, int shift_w) {
    int i;
    secp256k1_num_word carry = 0;
    for (i = 0; i < shift_w; ++i) {
        r->data[i] = 0;
    }
    for (i = shift_w; i < NUM_N_WORDS; ++i) {
        secp256k1_num_dword temp = ((secp256k1_num_dword) a->data[i - shift_w]) * w + carry;
        r->data[i] = temp;
        carry = temp >> NUM_WORD_WIDTH;
    }
}

static void secp256k1_num_lin_comb(secp256k1_num *ra, secp256k1_num *rb, const secp256k1_num *a, const secp256k1_num *b, secp256k1_num_sword *mat) {
    int i;
    secp256k1_num_sword carrya = 0, carryb = 0;
    for (i = 0; i < NUM_N_WORDS; ++i) {
        secp256k1_num_dword dworda = (secp256k1_num_dword) mat[0] * a->data[i] + (secp256k1_num_dword) mat[1] * b->data[i] + carrya;
        secp256k1_num_dword dwordb = (secp256k1_num_dword) mat[2] * a->data[i] + (secp256k1_num_dword) mat[3] * b->data[i] + carryb;
        carrya = dworda >> NUM_WORD_WIDTH;
        carryb = dwordb >> NUM_WORD_WIDTH;
        ra->data[i] = dworda;
        rb->data[i] = dwordb;
    }
}

static void secp256k1_num_lshift_word(secp256k1_num *r, const secp256k1_num *a, int bits) {
    if (bits > 0) {
        int i;
        r->data[NUM_N_WORDS - 1] = a->data[NUM_N_WORDS - 1] << bits;
        for (i = NUM_N_WORDS - 2; i >= 0; --i) {
            r->data[i + 1] += a->data[i] >> (NUM_WORD_WIDTH - bits);
            r->data[i] = a->data[i] << bits;
        }
    } else {
        memcpy(r, a, sizeof(*a));
    }
}

SECP256K1_INLINE static void secp256k1_num_leading_digit(secp256k1_num_word *rdigit, int *rindex, secp256k1_num *a) {
    *rindex = NUM_N_WORDS;
    *rdigit = 0;
    while (*rdigit == 0) {
        --*rindex;
        *rdigit = a->data[*rindex];
    }
}

/* this is not public since it computes multiplication mod 2^320 in the 64-bit
 * implementation, mod 2^288 in 32-bit. in other words overflow is undefined
 * behaviour wrt the num.h API, and it's really easy outside of specific cases.
 * Also b may be negative but a may not be. */
static void secp256k1_num_mul(secp256k1_num *r, const secp256k1_num * SECP256K1_RESTRICT a, const secp256k1_num * SECP256K1_RESTRICT b) {
    if (secp256k1_num_is_neg(b)) {
        /* if b is negative, we negate it, then negate the result */
        int i;
        memset(r, -1, sizeof(*r));
        /* loop through a */
        for (i = 0; i < NUM_N_WORDS; ++i) {
            if (a->data[i] > 0) {
                int j;
                unsigned borrow = 0;
                secp256k1_num_word carry = 0;
                /* loop through b */
                for (j = 0; i + j < NUM_N_WORDS; ++j) {
                    secp256k1_num_word b_word = -b->data[j] - borrow;
                    secp256k1_num_dword prod = ((secp256k1_num_dword) a->data[i]) * b_word + carry;
                    carry = (prod >> NUM_WORD_WIDTH) + (r->data[i + j] < (secp256k1_num_word) prod);
                    /* Subtract starting from 0xFF..FF rather than add starting
                     * from zero to bit-invert the individual words... */
                    r->data[i + j] -= prod;
                    borrow |= b_word != 0;
                }
            }
        }
        /* ...then add one to complete the twos-complement negation of r */
        i = 0;
        do {
            ++r->data[i];
        } while(r->data[i++] == 0);
    } else {
        int i;
        memset(r, 0, sizeof(*r));
        /* loop through a */
        for (i = 0; i < NUM_N_WORDS; ++i) {
            if (a->data[i] > 0) {
                int j;
                secp256k1_num_word carry = 0;
                /* loop through b */
                for (j = 0; i + j < NUM_N_WORDS; ++j) {
                    secp256k1_num_dword prod = ((secp256k1_num_dword) a->data[i]) * b->data[j] + carry;
                    r->data[i + j] += prod;
                    carry = (prod >> NUM_WORD_WIDTH) + (r->data[i + j] < (secp256k1_num_word) prod);
                }
            }
        }
    }
}

/* computes r, q such that a = q*m + r, where a is a bignum and m is a word */
static int secp256k1_num_div_mod_1(secp256k1_num *rq, secp256k1_num *rr, const secp256k1_num *a, secp256k1_num_word m) {
    /* This is a simplifed version of `secp256k1_num_div_mod` which takes a
     * one-word modulus. Because the divisor does not need to be truncated,
     * we can take top_{1,2}_words_of_dividend / top_word_of_divisor to get
     * the exact digits of the quotient without any correction steps.
     */
    int i;
    int ret = 0;
    secp256k1_num sub = {{0}};

    memset(rq, 0, sizeof(*rq));
    *rr = *a;
    /* Special case: top word of dividend is greater than divisor */
    if (rr->data[NUM_N_WORDS - 1] >= m) {
        rq->data[NUM_N_WORDS - 1] = rr->data[NUM_N_WORDS - 1] / m;
        sub.data[NUM_N_WORDS - 1] = m * rq->data[NUM_N_WORDS - 1];
        secp256k1_num_sub(rr, rr, &sub);
        ret = NUM_N_WORDS - 1;
    }
    /* Loop, dividing top -two- words of dividend by the divisor */
    for (i = NUM_N_WORDS - 2; i >= 0; --i) {
        secp256k1_num_dword topr = (((secp256k1_num_dword) rr->data[i + 1]) << NUM_WORD_WIDTH) + rr->data[i];
        rq->data[i] = topr / m;
        if (rq->data[i] > 0) {
            /* Since our product is only two words, we can collapse all of
             * `secp256k1_num_div_mul_word` to this. */
            secp256k1_num_dword prod = ((secp256k1_num_dword) m) * rq->data[i];
            sub.data[i + 1] = prod >> NUM_WORD_WIDTH;
            sub.data[i] = prod;
            secp256k1_num_sub(rr, rr, &sub);
            sub.data[i + 1] = sub.data[i] = 0;
            if (ret == 0)
                ret = i;
        }
    }
    return ret;
}

/* computes r, q such that a = q*m + r */
static int secp256k1_num_div_mod(secp256k1_num *rq, secp256k1_num *rr, const secp256k1_num *a, const secp256k1_num *m) {
    /* This division algorithm is a standard one which I believe originally
     * occurs in Knuth 4.3.1. This code derived from the derivation and
     * explanation given by William Hart at
     *     http://wbhart.blogspot.de/2010/10/bsdnt-divrem-discussion.html
     * It is a long division algorithm which computes each word of the
     * result by dividing the top 1 or 2 words of the dividend by the top
     * word of the divisor; the result is guaranteed to be within 2 of the
     * correct word, so a quick correction can be done. Call the result
     * q. We then subtract q times the divisor from the dividend and continue
     * until it is smaller than the divisor. These q's are the words of our
     * quotient and the remaining dividend is our remainder.
     *
     * The "core" of the algorithm is the dword-by-word division, which is
     * something a lot of research has gone into. For now we use the
     * uint128_t type and trust the gcc developers to have done something
     * fast, but there may be opportunity for optimization there.
     *
     * To get this "off by at most 2" guarantee on the division X/Y of the
     * truncated dividend by the truncated divisor, we require that
     *
     *    B * Y >= X    and    Y >= B/2
     *
     * where B = 2^64 is our word size. The first inequality simply makes
     * sure we're computing only one word at a time; if it does not hold,
     * we just divide X by B to reduce it from two words to one. The second
     * one is more important; its justification is given in the above link.
     * Essentially it says that Y must have its high bit set to 1. We obtain
     * this by left-shifting both dividend and divisor before starting the
     * division.
     *
     * Notice that Y never changes: the dividend is reduced to the remainder
     * throughout the division but the quotient is untouched. Therefore this
     * shift only needs to happen once.
     */
    int shift_w, shift_b;
    secp256k1_num_word rem_high;  /* This slides as rem decreases */
    secp256k1_num_word div_high;  /* This one stays constant */
    secp256k1_num div;
    int output_idx;
    int ret = 0;
    int i;

    /* Shift divisor and dividend to get high bit of divisor to 1 */
    secp256k1_num_div_get_shifts(&shift_w, &shift_b, m);
    VERIFY_CHECK(shift_w < NUM_N_WORDS);
    VERIFY_CHECK(shift_b < NUM_WORD_WIDTH);
    /* Special case division by one word, which can be done without correction
     * steps or normalization */
    if (shift_w == NUM_N_WORDS - 1) {
        return secp256k1_num_div_mod_1(rq, rr, a, m->data[0]);
    }

#ifdef VERIFY
    /* If the high word of rr was too large (which is a little hard to do because
     * it can't be set directly and we don't expose a multiply function, but can
     * happen if the divisor's high word is very small), the following shift may be
     * destructive. This cannot be prevented while using fixed-size arrays (except
     * by creating a larger num_t type for use only inside this function) so we
     * declare it to be a bug in the caller. The library should only call this
     * function with a divisor which is <= 2^256. */
{
    secp256k1_num temp;
    secp256k1_num_lshift_word(&temp, a, shift_b);
    secp256k1_num_shift(&temp, shift_b);
    CHECK(secp256k1_num_eq(&temp, a));
}
#endif

    /* Do the shifts after the special case, both to save time, and because if
     * either `a` or `m` aliases either of `rr` or `rq`, the values passed into
     * `secp256k1_num_div_mod_1` above would be corrupted by them. */
    secp256k1_num_lshift_word(&div, m, shift_b);
    secp256k1_num_lshift_word(rr, a, shift_b);

    /* Locate highest word of the dividend and quotient. Note that after our left
     * shift, we could be using all five words of the dividend, even if it originally
     * had the top word clear. */
    secp256k1_num_leading_digit(&rem_high, &i, rr);
    div_high = div.data[NUM_N_WORDS - 1 - shift_w];

    /* Compute index of high word of the quotient. Notice that this is
     * maximum 4. To get five output words (e.g. when dividing a five
     * word number by a small one-word number) we necessarily use the
     * special case described in the next comment. */
    output_idx = shift_w - (NUM_N_WORDS - 1 - i);

    /* Zero out the whole quotient since we will only set its low words later on */
    memset(rq, 0, sizeof(*rq));

    /* If we're dividing a small number by a bigger one, we know the answer is 0 */
    if (output_idx < 0)
        goto finish_div;

    /* Normally we need the top two words of the remainder. However, if
     * the highest word alone exceeds the top word of the quotient, we
     * need only this word (and using two would give us a "word" that
     * exceeded our base). This can only happen on the first iteration,
     * so we special-case it here before starting the real algorithm. */
    if (rem_high >= div_high) {
        secp256k1_num sub;
        secp256k1_num_word q = rem_high / div_high;
        secp256k1_num_div_mul_word(&sub, &div, q, output_idx);
        /* Correct for error in the quotient. This was a while loop, but as it is
         * mathematically guaranteed to iterate at most twice, we can unroll it
         * into a pair of nested ifs. Note that we are guaranteed q > 0 here by
         * virtue of being in this if block. */
        if (secp256k1_num_cmp (&sub, rr) >= 0) {
            secp256k1_num_sub_shift_word (&sub, &sub, &div, output_idx, i + 1);
            --q;
            if (secp256k1_num_cmp (&sub, rr) >= 0) {
                secp256k1_num_sub_shift_word (&sub, &sub, &div, output_idx, i + 1);
                --q;
            }
        }
        /* Reduce remainder */
        secp256k1_num_sub_shift_word(rr, rr, &sub, 0, i + 1);
        rq->data[output_idx] = q;
        if (q != 0) {
            ret = output_idx;
        }
    }

    /* Loop down through the words of the dividend */
    while (output_idx > 0) {
        secp256k1_num_dword rem_high2 = ((secp256k1_num_dword) rr->data[i] << NUM_WORD_WIDTH) + rr->data[i - 1];
        /* This is identical to the special-case above, except with
         * rem_high2 in place of rem_high */
        secp256k1_num_word q = rem_high2 / div_high;
        /* The q we just computed is at most 2 greater than the correct quotient.
         * If the correct quotient is (uint64_t) -1 or (uint64_t) -2, this means
         * q may overflow the uint64_t type. We catch this and do a pre-correction. */
        if (rr->data[i] == div_high)
            q = (secp256k1_num_word) -1;
        if (q > 0) {
            secp256k1_num sub;
            /* We then compute the amount to subtract, and do the "real" corrections. */
            secp256k1_num_div_mul_word(&sub, &div, q, output_idx - 1);
            /* Correct for error in the quotient. This was a while loop, but as it is
             * mathematically guaranteed to iterate at most twice, we can unroll it
             * into a pair of nested ifs. */
            if (secp256k1_num_cmp (&sub, rr) >= 0) {
                secp256k1_num_sub_shift_word (&sub, &sub, &div, output_idx - 1, i + 1);
                --q;
                if (secp256k1_num_cmp (&sub, rr) >= 0) {
                    secp256k1_num_sub_shift_word (&sub, &sub, &div, output_idx - 1, i + 1);
                    --q;
                }
            }
            rq->data[output_idx - 1] = q;
            if (ret == 0 && q != 0)
                ret = output_idx - 1;
            secp256k1_num_sub_shift_word(rr, rr, &sub, 0, i + 1);
        }
        --output_idx;
        --i;
    }

finish_div:
    /* Correct the remainder for the left-shifting we did at the beginning */
    secp256k1_num_shift (rr, shift_b);
    return ret;
}
/* end div_mod */

SECP256K1_INLINE static void secp256k1_num_mod(secp256k1_num *r, const secp256k1_num *m) {
    secp256k1_num quot;
    VERIFY_CHECK(!secp256k1_num_is_zero(m));
    secp256k1_num_div_mod(&quot, r, r, m);
}

/* start mod inverse */
/* As described in http://www.imsc.res.in/~kapil/crypto/notes/node11.html,
 * if the division step in Euclid's gcd algorithm is a single word, there
 * is a good chance we can compute it just by dividing the top words of
 * the dividend and divisor. In this case we can avoid a long-division.
 * We do this as many times as we can, only ever using the top words, then
 * return the resulting linear transformation that will then be applied
 * to the full 256-bit values. */
static void secp256k1_num_gcd_lehmer(secp256k1_num_sword *rmat, secp256k1_num_word x, secp256k1_num_word y) {
    rmat[0] = 1; rmat[1] = 0; rmat[2] = 0; rmat[3] = 1;
    /* Iterate, left-multiplying it by [[0 1] [1 -w]] as many times as we can. */
    while (1) {
        /* Check whether we can iterate; that is, whether the ratio of the
         * leading digits is guaranteed to be the ratio of the full numbers.
         * This will be true if w1 == w2. Note that we need to check for
         * division by 0 since it is possible one is undefined. */
        secp256k1_num_sword w1, w2;
        if (y + rmat[2] != 0 && y + rmat[3] != 0) {
            w1 = (x + rmat[0]) / (y + rmat[2]);
            w2 = (x + rmat[1]) / (y + rmat[3]);
        } else break;

        if (w1 == w2) {
            /* If so, update the matrix... */
            const secp256k1_num_sword c = rmat[2];
            const secp256k1_num_sword d = rmat[3];
            rmat[2] = rmat[0] - w1 * c;
            rmat[3] = rmat[1] - w1 * d;
            rmat[0] = c;
            rmat[1] = d;
            /* ...and the digits */
            w2 = x;       /* w2 is used as a temp here */
            x = y;
            y = w2 - w1*y;
        } else break;
    }
}

/* Iterate through x and y doing the whole gcd with int math */
static void secp256k1_num_gcd_word(secp256k1_num_sword *rmat, secp256k1_num_word x, secp256k1_num_word y) {
    rmat[0] = 1; rmat[1] = 0; rmat[2] = 0; rmat[3] = 1;
    /* Iterate, left-multiplying it by [[0 1] [1 -w]] as many times as we can. */
    while (y != 0) {
        secp256k1_num_word q = x / y;
        /* Update the matrix... */
        const secp256k1_num_word t = x;
        const secp256k1_num_word c = rmat[2];
        const secp256k1_num_word d = rmat[3];
        rmat[2] = rmat[0] - q * c;
        rmat[3] = rmat[1] - q * d;
        rmat[0] = c;
        rmat[1] = d;
        /* ...and the digits */
        x = y;
        y = t - q*y;
    }
}

static void secp256k1_num_mod_inverse(secp256k1_num *rr, const secp256k1_num *a, const secp256k1_num *m)
{
    secp256k1_num r2 = {{1, 0, 0, 0, 0}};
    secp256k1_num b1 = *m, b2 = *a;
    secp256k1_num quot;

    secp256k1_num_sword mat[4];
    memset(rr, 0, sizeof(*rr));

    while(!secp256k1_num_is_zero(&b2)) {
        int high_idx;
        secp256k1_num temp;

        /** lehmer step **/
        int index[2];
        secp256k1_num_word x, y;
        /* Euclid's GCD algorithm works by applying the matrix
         * [[0 1] [1 -w]] repeatedly to the vectors [b1 b2] and
         * [rr r2], where w is the integer quotient b1/b2.
         * This optimization, due to Lehmer, lets us shortcut several
         * iterations by computing w using only the leading digits
         * of b1 and b2. We multiply the resective matrices together
         * and apply the resulting transformation b1 and b2, avoiding
         * bignum operations until the very end.
         * 
         * Lehmer's algorithm quits when it becomes unsure whether it
         * can compute the next quotient w or not; then we need to do
         * an (expensive) long division to compute the next quotient
         * properly. Turns out that by applying the resulting linear
         * transformation then just restarting Lehmer (without any long
         * division) you can get some more iterations. So we put this
         * in a while loop. */
        secp256k1_num_leading_digit(&x, &index[0], &b1);
        secp256k1_num_leading_digit(&y, &index[1], &b2);
        while (index[0] == index[1]) {
            /* Check whether we can just finish the whole thing with
             * machine words */
            if (index[0] == 0) {
                secp256k1_num_gcd_word(mat, x, y);
                /* Don't need to update [b1 b2] */
                secp256k1_num_lin_comb(rr, &r2, rr, &r2, mat);
                goto done;
            }
            secp256k1_num_gcd_lehmer(mat, x, y);
            if (mat[1] == 0)
                break;
            secp256k1_num_lin_comb(&b1, &b2, &b1, &b2, mat);
            secp256k1_num_lin_comb(rr, &r2, rr, &r2, mat);

            /* Because we know our gcd will be one for our applications,
             * the last iteration before b2 == 0 will have b2 == 1, a
             * condition under which the Lehmer iteration is unable to
             * compute the next digit (it computes the next digit as
             * (b1 + 1) / b2 and b1 / (b2 + 1), which reduce to (b1 + 1)
             * vs b1 / 2, which of course will differ. What this means is
             * that we do not need to check for b2 == 0 before going to
             * the next step; we know it won't be. */
            VERIFY_CHECK(!secp256k1_num_is_zero(&b2));
            secp256k1_num_leading_digit(&x, &index[0], &b1);
            secp256k1_num_leading_digit(&y, &index[1], &b2);
        }
        /** long division step **/
        /* b2 <- b1 - b2 * quot */
        temp = b2;
        if (index[1] == 0)
            high_idx = secp256k1_num_div_mod_1 (&quot, &b2, &b1, b2.data[0]);
        else
            high_idx = secp256k1_num_div_mod (&quot, &b2, &b1, &b2);
        b1 = temp;
        /* Even though we had to do a long division, chances are that
         * the quotient is one digit, and we can use lin_comb to compute
         * the next iteration rather than num_mul and num_sub. */
        /* r2 <- rr - r2 * quot */
        if (high_idx == 0 && (secp256k1_num_sword) quot.data[0] >= 0) {
            /* It is possible to do some Lehmer iterations on the matrix
             * [[ 0 1 ] [ 1 -w ]] before applying it to [rr r2]. We'd
             * also need to update [b1 b2], which has already been
             * iterated on. We'd accomplish this by right-multiplying
             * by [[ 0 1 ] [ 1 -w ]]^{-1} = [[ w 1 ] [ 1 0 ]] before
             * applying the matrix. to [b1 b2]. However, it turns out
             * this is a perf *loss*. I'm unsure why. So we don't.  */
            mat[0] = 0; mat[1] = 1; mat[2] = 1; mat[3] = -quot.data[0];
            secp256k1_num_lin_comb(rr, &r2, rr, &r2, mat);
        } else {
            temp = r2;
            secp256k1_num_mul(&r2, &quot, &temp);
            secp256k1_num_sub(&r2, rr, &r2);
            *rr = temp;
        }
    }
done:
    if (secp256k1_num_is_neg(rr)) {
        secp256k1_num_add(rr, rr, m);
    }
}
/* end mod inverse */

#endif
