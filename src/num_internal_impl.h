// Copyright (c) 2014 Cory Fields
// Distributed under the MIT/X11 software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef _SECP256K1_NUM_REPR_IMPL_H_
#define _SECP256K1_NUM_REPR_IMPL_H_

#include <assert.h>
#include <string.h>
#include <stdlib.h>
#include <limits.h>
#include <gmp.h>

#include "util.h"
#include "num.h"

struct bn_limb_double
{
  bn_limb high;
  bn_limb low;
};


#if 0
void print_bn_reverse(const char* s, const secp256k1_num_t* r)
{
  printf("%s: limbs: %i. neg: %i. data:",s, r->limbs, r->neg);
  for (int i = r->limbs; i != 0; i--)
      printf("%016lx",r->data[i-1]);
  printf("\n");
}
#endif

#ifdef VERIFY
void static secp256k1_num_sanity(const secp256k1_num_t *a) {
    VERIFY_CHECK(a->limbs == 1 || (a->limbs > 1 && a->data[a->limbs-1] != 0));
}
#else
#define secp256k1_num_sanity(a) do { } while(0)
#endif

void static secp256k1_num_init(secp256k1_num_t *r) {
    r->neg = 0;
    r->limbs = 1;
    for(int i = 0; i != NUM_LIMBS*2; i++)
      r->data[i] = 0;

}

void static secp256k1_num_clear(secp256k1_num_t *r) {
    memset(r, 0,sizeof(*r));
}

void static secp256k1_num_free(secp256k1_num_t *r) {
}

void static secp256k1_num_copy(secp256k1_num_t *r, const secp256k1_num_t *a) {
    *r = *a;
}

int static secp256k1_num_bits(const secp256k1_num_t *a) {
    int ret = (a->limbs-1)*INT_NUM_BITS;
    bn_limb x = a->data[a->limbs-1];
    while(x) {
        x >>= 1;
        ret++;
    }
    return ret;

}


void static secp256k1_num_get_bin(unsigned char *r, unsigned int rlen, const secp256k1_num_t *a) {
  unsigned char tmp[65] = {};
  int len = 0;
  for(int i = a->limbs; i != 0; i--)
  {
    for(int j = 0; j != (sizeof a->data[0]); j++)
      tmp[len++]=(a->data[i-1] >> (CHAR_BIT*((sizeof a->data[0])-j-1))) & UCHAR_MAX;
  }
  int shift = 0;
  while (shift < len && tmp[shift] == 0) shift++;
  VERIFY_CHECK(len-shift <= rlen);
  memset(r, 0, rlen - len + shift);
  if (len > shift)
  {
    memcpy(r + rlen - len + shift, tmp + shift, len - shift);
  }
    memset(tmp, 0, sizeof(tmp));
}

void static secp256k1_num_set_bin(secp256k1_num_t *r, const unsigned char *a, unsigned int alen) {
    VERIFY_CHECK(alen > 0);
    VERIFY_CHECK(alen <= 64);
   unsigned int count = alen;
   r->neg = 0;
   r->limbs = 0;

   r->data[0] = 0;
   while (count >= sizeof(r->data[0]))
   {
     for(int i = 0; i != sizeof(r->data[0]); i++)
       r->data[r->limbs] |= (bn_limb)a[count - 1 - i] << (i*CHAR_BIT);
     count-=sizeof(r->data[0]);
     r->limbs++;
     r->data[r->limbs] = 0;
   }
   for(int i = 0; i != count; i++)
     r->data[r->limbs] |= (bn_limb)a[count - 1 - i] << (i*CHAR_BIT);
   if (r->data[r->limbs])
     r->limbs++;
  while (r->limbs > 1 && r->data[r->limbs-1]==0) r->limbs--;
}

void static secp256k1_num_set_int(secp256k1_num_t *r, int a) {
    r->limbs = 1;
    r->neg = (a < 0);
    r->data[0] = (a < 0) ? -a : a;
}

bn_limb static inline  __attribute__((always_inline)) secp256k1_num_add_carry(const bn_limb a, const bn_limb b, const bn_limb carryin, bn_limb* carryout)
{
#if defined(BUILTIN_ADDCL)
  return __builtin_addcl(a, b, carryin, carryout);
#elif defined(HAVE___INT128)
   __int128 result = (__int128)a + (__int128)b + carryin;
  *carryout = result > (bn_limb)-1;
  return result;
#else
    bn_limb ret = a + b + carryin;
    *carryout = ((ret < a) || (ret < b) || (carryin && (a == (bn_limb)-1 && b == (bn_limb)-1)));
    return ret;
#endif
}

void static secp256k1_num_add_abs(secp256k1_num_t *r, const secp256k1_num_t *a, const secp256k1_num_t *b) {
  bn_limb carry = 0;
  for (int i = 0; i != a->limbs; i++)
    r->data[i] = secp256k1_num_add_carry(a->data[i],  b->data[i], carry, &carry);
  r->limbs = a->limbs;
  if(carry)
    r->data[r->limbs++] = 1;
}

void static secp256k1_num_sub_abs(secp256k1_num_t *r, const secp256k1_num_t *a, const secp256k1_num_t *b) {
  int borrow = 0;
  int nonzero = 0;
  int j;
  secp256k1_num_t copy;
  secp256k1_num_copy(&copy,a);
  r->limbs = a->limbs;
  copy.neg=r->neg;
  bn_limb ret;
  for (int i = 0; i != copy.limbs; i++)
  {
    ret = copy.data[i] - b->data[i];
    if (ret > copy.data[i])
      borrow = 1;
    copy.data[i] = ret;

    j = i+1;
    while(borrow)
    {
      VERIFY_CHECK(j != copy.limbs);
      if (copy.data[j] != 0)
        borrow = 0;
      copy.data[j] = copy.data[j]-1;
      j++;
    }

    if (ret != 0)
      nonzero = i;
  }

  copy.limbs = nonzero + 1;
  secp256k1_num_copy(r,&copy);
}

void static secp256k1_num_mod(secp256k1_num_t *r, const secp256k1_num_t *m) {

    secp256k1_num_sanity(r);
    secp256k1_num_sanity(m);

    if (r->limbs >= m->limbs) {
        mp_limb_t t[2*NUM_LIMBS];
        mpn_tdiv_qr(t, r->data, 0, r->data, r->limbs, m->data, m->limbs);
        memset(t, 0, sizeof(t));
        r->limbs = m->limbs;
        while (r->limbs > 1 && r->data[r->limbs-1]==0) r->limbs--;
    }

    if (r->neg && (r->limbs > 1 || r->data[0] != 0)) {
        secp256k1_num_sub_abs(r, m, r);
        r->neg = 0;
    }
}

int static secp256k1_num_is_zero(const secp256k1_num_t *a) {
    return (a->limbs == 1 && a->data[0] == 0);
}

int static secp256k1_num_is_odd(const secp256k1_num_t *a) {
    return a->data[0] & 1;
}

int static secp256k1_num_is_neg(const secp256k1_num_t *a) {
    return (a->limbs > 1 || a->data[0] != 0) && a->neg;
}

int static secp256k1_num_cmp(const secp256k1_num_t *a, const secp256k1_num_t *b) {
    if (a->limbs > b->limbs) return 1;
    if (a->limbs < b->limbs) return -1;
    for(int i = a->limbs - 1; i != -1; i--)
    {
      if (a->data[i] > b->data[i]) return 1;
      if (a->data[i] < b->data[i]) return -1;
    }
    return 0;
}

int static secp256k1_num_eq(const secp256k1_num_t *a, const secp256k1_num_t *b) {
    if (a->limbs > b->limbs) return 0;
    if (a->limbs < b->limbs) return 0;
    if ((a->neg && !secp256k1_num_is_zero(a)) != (b->neg && !secp256k1_num_is_zero(b))) return 0;
    for(int i = 0; i != a->limbs; i++)
      if (a->data[i] != b->data[i]) return 0;
    return 1;
}

void static secp256k1_num_subadd(secp256k1_num_t *r, const secp256k1_num_t *a, const secp256k1_num_t *b, int bneg) {
    if (!(b->neg ^ bneg ^ a->neg)) { // a and b have the same sign
        r->neg = a->neg;
        if (a->limbs >= b->limbs) {
            secp256k1_num_add_abs(r, a, b);
        } else {
            secp256k1_num_add_abs(r, b, a);
        }
    } else {
        if (secp256k1_num_cmp(a, b) > 0) {
            r->neg = a->neg;
            secp256k1_num_sub_abs(r, a, b);
        } else {
            r->neg = b->neg ^ bneg;
            secp256k1_num_sub_abs(r, b, a);
        }
    }
}

void static secp256k1_num_add(secp256k1_num_t *r, const secp256k1_num_t *a, const secp256k1_num_t *b) {
    secp256k1_num_sanity(a);
    secp256k1_num_sanity(b);
    secp256k1_num_subadd(r, a, b, 0);
}

void static secp256k1_num_sub(secp256k1_num_t *r, const secp256k1_num_t *a, const secp256k1_num_t *b) {
    secp256k1_num_sanity(a);
    secp256k1_num_sanity(b);
    secp256k1_num_subadd(r, a, b, 1);
}

void bn_limb_double_mult_add(secp256k1_num_t *r, struct bn_limb_double* a, int num, int shift)
{
  bn_limb carry = 0;
  for(int i = 0; i != shift; i++)
  {
    r->data[i] = 0;
  }
  r->data[shift+num] = 0;
  r->data[shift] = a[0].low;
  r->data[shift+1] = a[0].high;
  bn_limb temp = 0;
  for (int i = 1; i != num; i++)
  {
    r->data[i+shift] = secp256k1_num_add_carry(r->data[i+shift], a[i].low, carry, &carry);
    r->data[i+shift+1] = a[i].high;
  }
  r->data[num+shift]+=carry;
  r->limbs=num+shift+(carry || (a[num - 1].high != 0));
}

void bn_limb_double_mult(struct bn_limb_double* r, const bn_limb a, const bn_limb b)
{
#if HAVE___INT128
   __int128 result = (__int128)a * (__int128)b;
    r->low = (bn_limb)result;
    r->high = result >> 64;
#else
  bn_limb h1,l1,h2,l2;
  bn_limb a1,a2,a3;

  h1 = a >> SHIFT_SIZE;
  l1 = a & SHIFT_MASK;
  h2 = b >> SHIFT_SIZE;
  l2 = b & SHIFT_MASK;

  a1 = l2 * l1;
  a2 = l2 * h1;
  a3 = h2 * l1;

  r->high =   (h1 * h2) + (a2 >> SHIFT_SIZE) + (a3 >> SHIFT_SIZE);
  r->low  =   (a3 & SHIFT_MASK) + (a2 & SHIFT_MASK) + (a1 >> SHIFT_SIZE);
  r->high +=  r->low >> SHIFT_SIZE;
  r->low  <<= SHIFT_SIZE;
  r->low  +=  (a1 & SHIFT_MASK);
#endif
}


void static secp256k1_num_mul(secp256k1_num_t *r, const secp256k1_num_t *a, const secp256k1_num_t *b)
{
  secp256k1_num_sanity(a);
  secp256k1_num_sanity(b);
  VERIFY_CHECK(a->limbs + b->limbs <= 2*NUM_LIMBS+1);
  if ((a->limbs==1 && a->data[0]==0) || (b->limbs==1 && b->data[0]==0)) {
      r->limbs = 1;
      r->neg = 0;
      r->data[0] = 0;
      return;
  }
  struct bn_limb_double s[NUM_LIMBS*NUM_LIMBS];
  secp256k1_num_t temp;
  const secp256k1_num_t *c = a;
  const secp256k1_num_t *d = b;
  if (d->limbs > c->limbs)
  {
    c = b;
    d = a;
  }
  int neg = c->neg ^ d->neg;
  temp.neg = neg;
  int k = 0;
  for (int i = 0; i != d->limbs; i++)
  {
    for (int j = 0; j != c->limbs; j++)
      bn_limb_double_mult(&s[k++],c->data[j],d->data[i]);
  }
  int climbs = c->limbs;
  int dlimbs = d->limbs;
  int finallimbs = climbs;

  for(int i = 0; i != 2*NUM_LIMBS; i++)
    r->data[i] = 0;

  bn_limb_double_mult_add(r,&s[0],climbs,0);
  for (int i = 1; i != dlimbs; i++)
  {
    bn_limb_double_mult_add(&temp,&s[i*climbs],climbs,i);
    if (finallimbs > temp.limbs)
      secp256k1_num_add_abs(r,r,&temp);
    else
      secp256k1_num_add_abs(r,&temp,r);
    finallimbs = r->limbs;
  }
  VERIFY_CHECK(r->limbs <= 2*NUM_LIMBS);
}

void static secp256k1_num_mod_mul(secp256k1_num_t *r, const secp256k1_num_t *a, const secp256k1_num_t *b, const secp256k1_num_t *m) {
    secp256k1_num_mul(r, a, b);
    secp256k1_num_mod(r, m);
}


int static secp256k1_num_shift(secp256k1_num_t *r, int bits) {
    VERIFY_CHECK(bits <= INT_NUM_BITS);
  int ret = r->data[0] ? (r->data[0] & ((1 << bits) - 1)) : 0;
  int shiftsize = ((INT_NUM_BITS) - bits);
  int shiftmask = (1 << bits) - 1;
  for (int i = 0; i != r->limbs - 1; i++)
  {
    r->data[i] >>= bits;
    r->data[i] |= ((r->data[i+1] & shiftmask) << shiftsize);
  }
  r->data[r->limbs - 1] >>= bits;

  if (r->data[r->limbs-1] == 0 && r->limbs > 1)
    r->limbs -= 1;
  return ret;
}

int static secp256k1_num_get_bit(const secp256k1_num_t *a, int pos) {
    return ((a->limbs)*INT_NUM_BITS > pos) && ((a->data[pos/INT_NUM_BITS] >> (pos % INT_NUM_BITS)) & 1);
}

void static secp256k1_num_inc(secp256k1_num_t *r) {
  r->data[0] = r->data[0]+1;
  if EXPECT((r->data[0] != 0),1)
    return;

  for (int i = 1; i != r->limbs; i++)
  {
    r->data[i] = r->data[i]+1;
    if (r->data[i])
      return;
  }
  r->data[r->limbs++] = 1;
}

void static secp256k1_num_set_hex(secp256k1_num_t *r, const char *a, int alen) {
    static const unsigned char cvt[256] = {
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 1, 2, 3, 4, 5, 6,7,8,9,0,0,0,0,0,0,
        0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0,10,11,12,13,14,15,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0,
        0, 0, 0, 0, 0, 0, 0,0,0,0,0,0,0,0,0,0
    };
    VERIFY_CHECK(alen <= 129);

    int len = 0;
    int i = 0;
    unsigned char num[65] = {};
    while (len < alen - 1)
    {
      num[i] = (cvt[(unsigned char)a[len++]] << 4);
      num[i++] += cvt[(unsigned char)a[len++]];
    }
    if (len != alen)
      num[i++] = (cvt[(unsigned char)a[len++]]);
    secp256k1_num_set_bin(r,num,i);
}

void static secp256k1_num_get_hex(char *r, int rlen, const secp256k1_num_t *a) {
    static const unsigned char cvt[16] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'A', 'B', 'C', 'D', 'E', 'F'};
  unsigned char tmp[257] = {};
  int len = 0;
  for(int i = a->limbs; i != 0; i--)
  {
    for(int j = 0; j != (sizeof a->data[0]); j++)
    {
      if(len == rlen)
        break;
      tmp[len++]  = ((a->data[i-1] >> (CHAR_BIT*((sizeof a->data[0])-j-1))) >> 4) & 0xf;
      tmp[len++] = (a->data[i-1] >> (CHAR_BIT*((sizeof a->data[0])-j-1))) & 0xf;
    }
    if(len == rlen)
      break;
  }
    VERIFY_CHECK(len <= rlen);
    for (int i=0; i<len; i++) {
        VERIFY_CHECK(rlen-len+i >= 0);
        VERIFY_CHECK(rlen-len+i < rlen);
        VERIFY_CHECK(tmp[i] >= 0);
        VERIFY_CHECK(tmp[i] < 16);
        r[rlen-len+i] = cvt[tmp[i]];
    }
    for (int i=0; i<rlen-len; i++) {
        VERIFY_CHECK(i >= 0);
        VERIFY_CHECK(i < rlen);
        r[i] = cvt[0];
    }
}

void static secp256k1_num_split(secp256k1_num_t *rl, secp256k1_num_t *rh, const secp256k1_num_t *a, int bits) {
    VERIFY_CHECK(bits > 0);
    int hstart;
    rh->neg = a->neg;
    if (bits >= a->limbs * INT_NUM_BITS) {
        *rl = *a;
        rh->limbs = 1;
        rh->data[0] = 0;
        return;
    }
    rl->limbs = 0;
    rl->neg = a->neg;
    int left = bits;
    while (left >= INT_NUM_BITS) {
        rl->data[rl->limbs] = a->data[rl->limbs];
        rl->limbs++;
        left -= INT_NUM_BITS;
    }
    if (left > 0)
        rl->data[rl->limbs++] = a->data[rl->limbs] & ((((bn_limb)1) << left) - 1);

    hstart = rl->limbs + (left != 0);
    for(int i = 0; i != a->limbs - rl->limbs; i++)
    {
      rh->data[i] = a->data[hstart + i];
      rh->limbs++;
    }
    if (left)
      secp256k1_num_shift(rh,left);

    while (rl->limbs>1 && rl->data[rl->limbs-1]==0) rl->limbs--;
    while (rh->limbs>1 && rh->data[rh->limbs-1]==0) rh->limbs--;
}

void static secp256k1_num_negate(secp256k1_num_t *r) {
    r->neg ^= 1;
}

#endif
