#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "secp256k1.c"

/*** Scalar Operation ***/
/* Test commutativity of scalar addition */ 
static void fuzz_scalar_add_commutativty(const uint8_t *data, size_t size) {
    if (size >= 64) {        
        secp256k1_scalar a, b, r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_set_b32(&b, data + 32, NULL);
        secp256k1_scalar_add(&r1, &a, &b);
        secp256k1_scalar_add(&r2, &b, &a);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }
}

/* Test associativity of scalar addition */
static void fuzz_scalar_add_associativity(const uint8_t *data, size_t size) {
    if (size >= 96) {     
        secp256k1_scalar a, b, c, r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_set_b32(&b, data + 32, NULL);
        secp256k1_scalar_set_b32(&c, data + 64, NULL);       
        secp256k1_scalar_add(&r1, &a, &b);
        secp256k1_scalar_add(&r1, &r1, &c);
        secp256k1_scalar_add(&r2, &b, &c);
        secp256k1_scalar_add(&r2, &r2, &a);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }
}

/* Test identity addition */ 
static void fuzz_scalar_add_zero(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_scalar a, r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_add(&r1, &a, &secp256k1_scalar_zero);
        CHECK(secp256k1_scalar_eq(&r1, &a));
    }
}

/* Test scalar addition with its complement */ 
static void fuzz_scalar_add_complements(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_scalar a, r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_negate(&r1, &a);
        secp256k1_scalar_add(&r2, &a, &r1);
        CHECK(secp256k1_scalar_is_zero(&r2));
    }
}

/* Test commutativity of scalar multiplication */
static void fuzz_scalar_mul_commutativity(const uint8_t *data, size_t size) {
    if (size >= 64) {        
        secp256k1_scalar a, b, r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_set_b32(&b, data + 32, NULL);
        secp256k1_scalar_mul(&r1, &a, &b);
        secp256k1_scalar_mul(&r2, &b, &a);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }
}

/* Test associativity of scalar multiplication */
static void fuzz_scalar_mul_associativity(const uint8_t *data, size_t size) {
    if (size >= 96) {     
        secp256k1_scalar a, b, c, r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_set_b32(&b, data + 32, NULL);
        secp256k1_scalar_set_b32(&c, data + 64, NULL);       
        secp256k1_scalar_mul(&r1, &a, &b);
        secp256k1_scalar_mul(&r1, &r1, &c);
        secp256k1_scalar_mul(&r2, &b, &c);
        secp256k1_scalar_mul(&r2, &r2, &a);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }
}

/* Test distributivity of scalar multiplication */
static void fuzz_scalar_mul_distributivity(const uint8_t *data, size_t size) {
    if (size >= 96) {     
        secp256k1_scalar a, b, c, r1, r2, r3;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_set_b32(&b, data + 32, NULL);
        secp256k1_scalar_set_b32(&c, data + 64, NULL);       
        secp256k1_scalar_add(&r1, &a, &b);
        secp256k1_scalar_mul(&r1, &r1, &c);
        secp256k1_scalar_mul(&r2, &a, &c);
        secp256k1_scalar_mul(&r3, &b, &c);
        secp256k1_scalar_add(&r2, &r2, &r3);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }
}

/* Test identity multiplication */ 
static void fuzz_scalar_mul_one(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_scalar a, r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_mul(&r1, &a, &secp256k1_scalar_one);
        CHECK(secp256k1_scalar_eq(&r1, &a));
    }
}

/* Test scalar multiplication with zero */ 
static void fuzz_scalar_mul_zero(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_scalar a, r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_mul(&r1, &a, &secp256k1_scalar_zero);
        CHECK(secp256k1_scalar_is_zero(&r1));
    }
}

/* Test scalar inverse */
static void fuzz_scalar_inverse(const uint8_t *data, size_t size) {
    if (size >= 32) {     
        secp256k1_scalar a, r1, r2, r3;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_inverse(&r1, &a);
        if (secp256k1_scalar_is_zero(&a)) {
            CHECK(secp256k1_scalar_is_zero(&r1));
        } else {
            secp256k1_scalar_mul(&r2, &a, &r1);
            CHECK(secp256k1_scalar_is_one(&r2));
        }
    }
} 

/* Test scalar inverse (without constant-time guarantee) */
static void fuzz_scalar_inverse_var(const uint8_t *data, size_t size) {
    if (size >= 32) {     
        secp256k1_scalar a, r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_inverse_var(&r1, &a);
        if (secp256k1_scalar_is_zero(&a)) {
            CHECK(secp256k1_scalar_is_zero(&r1));
        } else {
            secp256k1_scalar_mul(&r2, &a, &r1);
            CHECK(secp256k1_scalar_is_one(&r2));
        }
    }
}             

/* Test scalar complement */ 
static void fuzz_scalar_negate(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_scalar a, r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_negate(&r1, &a);
        secp256k1_scalar_negate(&r2, &r1);
        CHECK(secp256k1_scalar_eq(&a, &r2));
    }
}

/* Test low bits shifted off */
static void fuzz_scalar_shift(const uint8_t *data, size_t size) {
    if (size >= 32) {
        int bit, r1, r2;     
        secp256k1_scalar a;
        secp256k1_scalar_set_b32(&a, data, NULL);
        bit = 1 + (data[31] % 15);
        r2 = a.d[0] % (1ULL << bit);
        r1 = secp256k1_scalar_shr_int(&a, bit);
        CHECK(r1 == r2);
    }
}

/* Test r1+r2*lambda = a */
static void fuzz_scalar_split_lambda(const uint8_t *data, size_t size) {
    if (size >= 32) {
        secp256k1_scalar a, r1, r2, r3;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_split_lambda(&r1, &r2, &a);
        secp256k1_scalar_mul(&r3, &secp256k1_const_lambda, &r2);
        secp256k1_scalar_add(&r3, &r3, &r1);
        CHECK(secp256k1_scalar_eq(&r3, &a));
    }    
}

/* Test conditional move of scalars  */
static void fuzz_scalar_cmov(const uint8_t *data, size_t size) {
    if (size >= 64) {        
        secp256k1_scalar a, b, r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_set_b32(&b, data + 32, NULL);
        int flag = size % 2;
        r1 = a;
        if (flag) {            
            secp256k1_scalar_cmov(&r1, &b, 1);
            CHECK(secp256k1_scalar_eq(&r1, &b));
        } else {
            secp256k1_scalar_cmov(&r1, &b, 0);
            CHECK(secp256k1_scalar_eq(&r1, &a));
        }
    }
}

/*** Field Operation ***/
/** Construct a valid field element using 42 bytes data from fuzzer.  
*
* On input, 'data' must have 42 bytes at least. If 'normalized' = 1, this function will only construct normalized field elements.
* If 'normalized' = 0, this function will construct normalized or non-normalized field elements depending on the fuzzer data. 
* 'max_magnitude' determines the max magnitude of field element generated from this function. 
* If 'normalized' = 1, ‘max_magnitude’ cannot exceed 1.  If 'normalized' = 0, ‘max_magnitude’ cannot exceed 32. 
* On output, r will be a valid field element
**/
static void fuzz_field_construct(const uint8_t *data, int normalized, int max_magnitude, secp256k1_fe *r) {
    /* Construct a field element using data[0...39] */
    for (int i = 0; i < 5; ++i) {
        r->n[i] = 0;
        for (int j = 0; j < 8; ++j) {
            r->n[i] |= (uint64_t)data[i * 8 + j] << ((7 - j) * 8);
        }
    }
    CHECK(max_magnitude <= 32);
    CHECK((normalized == 1 && max_magnitude <=1) || normalized == 0);
    /* Set a random magnitude depending on the data[40] */
    int magnitude = data[40] % (max_magnitude + 1);
    /* Set a random normalized depending on the data[41] (if magnitude <= 1) */
    int n = magnitude <= 1 ? (data[41] % 2) : 0;
    r->magnitude = magnitude;
    r->normalized = normalized ? 1 : n;
    int t = r->normalized ? 1 : (2 * magnitude);
    if (magnitude == 0){ 
        for (int i=0; i<5; i++) {
            r->n[i] = 0;
        }
    }  
    uint64_t mask1 = 0xFFFFFFFFFFFFFULL * t;
    uint64_t mask2 = 0x0FFFFFFFFFFFFULL * t;         
    r->n[0] &= mask1;
    r->n[1] &= mask1;
    r->n[2] &= mask1;
    r->n[3] &= mask1;
    r->n[4] &= mask2;
    if (r->normalized) {
        if ((r->n[4] == 0x0FFFFFFFFFFFFULL) && ((r->n[3] & r->n[2] & r->n[1]) == 0xFFFFFFFFFFFFFULL)) {
            uint64_t mask3 = 0xFFFFEFFFFFC2FULL;
            r->n[0] &= mask3;
            r->n[0] = (r->n[0] == 0xFFFFEFFFFFC2FULL) ? (r->n[0] - 1) : r->n[0];
        }
    }
}

/* Test the field element comparison operations. */
static void fuzz_field_comparison(const uint8_t *data, size_t size) {
    if (size >= 42) {
        secp256k1_fe a, b;    
        fuzz_field_construct(data, 1, 1, &a);
        b = a;
        CHECK(secp256k1_fe_cmp_var(&a, &b) == 0);
        secp256k1_fe_add_int(&b, 1);
        secp256k1_fe_normalize(&b);
        if (!secp256k1_fe_is_zero(&b)) {
            CHECK(secp256k1_fe_cmp_var(&a, &b) == -1);
            CHECK(secp256k1_fe_cmp_var(&b, &a) == 1);
        }       
    }
}

/* Test the equality of field elements. */
static void fuzz_field_equal(const uint8_t *data, size_t size) {
    if (size >= 42) {
        secp256k1_fe a, b, c;
        fuzz_field_construct(data, 0, 31, &a);
        b = a;
        secp256k1_fe_normalize(&b);
        c = a.magnitude <= 1 ? a : b;
        CHECK(secp256k1_fe_equal(&b, &a));
        secp256k1_fe_add_int(&c, 1);
        CHECK(secp256k1_fe_equal(&b, &c) == 0); 
    }  
}

/* Test conversions between 32-byte value and field element */ 
static void fuzz_field_b32_and_fe(const uint8_t *data, size_t size) {
    if (size >= 42) {
        secp256k1_fe a, b, c;
        unsigned char b32[32];     
        fuzz_field_construct(data, 1, 1, &a);  
        secp256k1_fe_get_b32(b32, &a);
        secp256k1_fe_set_b32_limit(&b, b32);
        secp256k1_fe_set_b32_mod(&c, b32);
        CHECK(secp256k1_fe_equal(&a, &b));
        CHECK(secp256k1_fe_equal(&a, &c));       
    }
}

/* Test conversions between field element and secp256k1_fe_storage */ 
static void fuzz_field_fe_and_storage(const uint8_t *data, size_t size) {
    if (size >= 42) {
        secp256k1_fe a, b;
        secp256k1_fe_storage fes; 
        fuzz_field_construct(data, 1, 1, &a);
        secp256k1_fe_to_storage(&fes, &a);
        secp256k1_fe_from_storage(&b, &fes);
        CHECK(secp256k1_fe_cmp_var(&a, &b) == 0);
    }
}

/* Test commutativity of addition on two field elements */ 
static void fuzz_field_add_commutativity(const uint8_t *data, size_t size) {
    if (size >= 84) {        
        secp256k1_fe a, b, r1, r2;
        fuzz_field_construct(data, 0, 32, &a);
        fuzz_field_construct(data + 42, 0, 32 - a.magnitude, &b);         
        r1 = a;
        secp256k1_fe_add(&r1, &b);
        r2 = b;
        secp256k1_fe_add(&r2, &a);    
        CHECK(r1.magnitude == a.magnitude + b.magnitude);
        CHECK(r2.magnitude == r1.magnitude);
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_normalize(&r2);
        /* Check a + b = b + a */
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);  
    }
}

/* Test associativity of addition on field elements */
static void fuzz_field_add_associativity(const uint8_t *data, size_t size) {
    if (size >= 126) {     
        secp256k1_fe a, b, c, r1, r2;
        fuzz_field_construct(data, 0, 32, &a);
        fuzz_field_construct(data + 42, 0, 32 - a.magnitude, &b);
        fuzz_field_construct(data + 84, 0, 32 - a.magnitude - b.magnitude, &c);
        r1 = a;
        secp256k1_fe_add(&r1, &b);
        secp256k1_fe_add(&r1, &c);
        r2 = c;
        secp256k1_fe_add(&r2, &b);
        secp256k1_fe_add(&r2, &a);
        CHECK(r1.magnitude == a.magnitude + b.magnitude + c.magnitude);
        CHECK(r2.magnitude == r1.magnitude);
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_normalize(&r2);
        /* Check a + b + c = a + (b + c) */
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);
    }
}

/* Test identity addition on field elements */ 
static void fuzz_field_add_zero(const uint8_t *data, size_t size) {
    if (size >= 42) {        
        secp256k1_fe a, zero, r1;
        fuzz_field_construct(data, 0, 32, &a);        
        secp256k1_fe_clear(&zero);
        r1 = a;
        secp256k1_fe_add(&r1, &zero);
        secp256k1_fe_normalize(&a);
        secp256k1_fe_normalize(&r1);
        /* Check a + 0 = a */
        CHECK(secp256k1_fe_cmp_var(&r1, &a) == 0);
    }
}

/* Test addition of field element and its negative value */ 
static void fuzz_field_add_negate(const uint8_t *data, size_t size) {
    if (size >= 42) {        
        secp256k1_fe a, negate;
        fuzz_field_construct(data, 0, 31, &a);
        secp256k1_fe_negate(&negate, &a, 31);
        CHECK(negate.magnitude == 32);
        secp256k1_fe_normalize(&a);
        secp256k1_fe_normalize(&negate);    
        secp256k1_fe_add(&a, &negate);
        /* Check a + -a = 0 */
        CHECK(secp256k1_fe_normalizes_to_zero(&a));
    }
}

/* Test addition of field element and its negative value (unchecked the m) */ 
static void fuzz_field_add_negate_unchecked(const uint8_t *data, size_t size) {
    if (size >= 43) {        
        secp256k1_fe a, negate;
        int m = data[42] % 32;
        fuzz_field_construct(data, 0, m, &a);        
        secp256k1_fe_negate_unchecked(&negate, &a, m);
        CHECK(negate.magnitude == m + 1);
        secp256k1_fe_normalize(&a);
        secp256k1_fe_normalize(&negate);    
        secp256k1_fe_add(&a, &negate);
        /* Check a + -a = 0 */
        CHECK(secp256k1_fe_normalizes_to_zero(&a));
    }
}

/* Test addition of field element and an integer */ 
static void fuzz_field_add_integer(const uint8_t *data, size_t size) {
    if (size >= 43) {        
        secp256k1_fe a, r1, r2;
        int v = data[42];
        fuzz_field_construct(data, 0, 31, &a);
        secp256k1_fe_set_int(&r1, v);
        secp256k1_fe_add(&r1, &a);
        r2 = a;
        secp256k1_fe_add_int(&r2, v);
        CHECK(r2.magnitude == a.magnitude + 1);
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_normalize(&r2);
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);
    }
}

/* Test the half value of a field element */ 
static void fuzz_field_half(const uint8_t *data, size_t size) {
    if (size >= 42) {
        secp256k1_fe a, b;
        fuzz_field_construct(data, 0, 31, &a);
        b = a;
        secp256k1_fe_half(&a);
        int m = b.magnitude;
        CHECK(a.magnitude == (m >> 1) + 1);
        secp256k1_fe_normalize(&a);
        secp256k1_fe_add(&a, &a);
        secp256k1_fe_normalize(&b);
        secp256k1_fe_normalize(&a);
        CHECK(secp256k1_fe_cmp_var(&a, &b) == 0);
    }
}

/* Test commutativity of multiplication on two field elements */
static void fuzz_field_mul_commutativity(const uint8_t *data, size_t size) {
    if (size >= 84) {        
        secp256k1_fe a, b, r1, r2;
        fuzz_field_construct(data, 0, 8, &a);
        fuzz_field_construct(data + 42, 0, 8, &b);
        secp256k1_fe_mul(&r1, &a, &b);
        secp256k1_fe_mul(&r2, &b, &a);
        CHECK((r1.magnitude == 1) && (r2.magnitude == 1));
        CHECK((r1.normalized == 0) && (r2.normalized == 0));
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_normalize(&r2);
        /* Check a * b = b * a */
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);     
    }
}

/* Test associativity of multiplication on field elements */
static void fuzz_field_mul_associativity(const uint8_t *data, size_t size) {
    if (size >= 126) {     
        secp256k1_fe a, b, c, r1, r2;
        fuzz_field_construct(data, 0, 8, &a);
        fuzz_field_construct(data + 42, 0, 8, &b);
        fuzz_field_construct(data + 84, 0, 8, &c);
        secp256k1_fe_mul(&r1, &a, &b);
        secp256k1_fe_mul(&r1, &r1, &c);
        secp256k1_fe_mul(&r2, &b, &c);
        secp256k1_fe_mul(&r2, &r2, &a);
        CHECK((r1.magnitude == 1) && (r2.magnitude == 1));
        CHECK((r1.normalized == 0) && (r2.normalized == 0));
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_normalize(&r2);
        /* Check a * b * c = a * (b * c) */
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);
    }
}

/* Test distributivity of multiplication on field elements */
static void fuzz_field_mul_distributivity(const uint8_t *data, size_t size) {
    if (size >= 126) {     
        secp256k1_fe a, b, c, r1, r2, r3;
        fuzz_field_construct(data, 0, 8, &a);
        fuzz_field_construct(data + 42, 0, 8, &b);
        fuzz_field_construct(data + 84, 0, 8, &c);
        r1 = a;       
        secp256k1_fe_add(&r1, &b);
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_mul(&r1, &r1, &c);
        secp256k1_fe_mul(&r2, &a, &c);
        secp256k1_fe_mul(&r3, &b, &c);
        secp256k1_fe_add(&r2, &r3);
        CHECK((r1.magnitude == 1) && (r2.magnitude == 2));
        CHECK((r1.normalized == 0) && (r2.normalized == 0));
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_normalize(&r2);
        /* Check a * (b + c) = a * b + a * c */
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);
    }
}

/* Test field multiplication with 0 */ 
static void fuzz_field_mul_zero(const uint8_t *data, size_t size) {
    if (size >= 42) {        
        secp256k1_fe a, zero, r1;
        fuzz_field_construct(data, 0, 8, &a);
        secp256k1_fe_clear(&zero);
        secp256k1_fe_mul(&r1, &a, &zero);
        CHECK(r1.magnitude == 1);
        CHECK(r1.normalized == 0);
        secp256k1_fe_normalize(&r1);
        CHECK(secp256k1_fe_is_zero(&r1));
    }
}

/* Test multiplication of field element with an integer */
static void fuzz_field_mul_integer(const uint8_t *data, size_t size) {
    if (size >= 42) {        
        secp256k1_fe a, r1, r2;
        fuzz_field_construct(data, 0, 2, &a);
        int m = a.magnitude;
        r1 = a;
        secp256k1_fe_mul_int(&r1, 16);
        CHECK(r1.magnitude == m * 16);
        CHECK(r1.normalized == 0);
        r2 = a;
        for (int i = 1; i < 16; ++i) {
            secp256k1_fe_add(&r2, &a);
        }
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_normalize(&r2);
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);
    }
}

/* Test square of a field element */
static void fuzz_field_sqr(const uint8_t *data, size_t size) {
    if (size >= 42) {        
        secp256k1_fe a, negate, r1, r2;
        fuzz_field_construct(data, 0, 7, &a);
        secp256k1_fe_sqr(&r1, &a);
        secp256k1_fe_negate_unchecked(&negate, &a, a.magnitude);
        secp256k1_fe_sqr(&r2, &negate);
        CHECK(r1.magnitude == 1);
        CHECK(r1.normalized == 0);
        CHECK(r2.magnitude == 1);
        CHECK(r2.normalized == 0);
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_normalize(&r2);
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);
        CHECK(secp256k1_fe_is_square_var(&r1)); 
    }
}

/* Test square root of a field element */
static void fuzz_field_sqrt(const uint8_t *data, size_t size) {
    if (size >= 42) {        
        secp256k1_fe a, b, negate, r1, r2, rn;
        fuzz_field_construct(data, 0, 8, &a);
        secp256k1_fe_sqr(&b, &a);
        secp256k1_fe_negate(&negate, &b, 1);
        secp256k1_fe_sqrt(&r1, &b);
        secp256k1_fe_sqrt(&rn, &negate);
        CHECK(secp256k1_fe_equal(&r1, &rn));
        CHECK(r1.magnitude == 1);
        CHECK(r1.normalized == 0);  
        secp256k1_fe_negate(&r2, &r1, 1);
        secp256k1_fe_add(&r1, &a); 
        secp256k1_fe_add(&r2, &a);
        secp256k1_fe_normalize(&r1); 
        secp256k1_fe_normalize(&r2);
        CHECK(secp256k1_fe_is_zero(&r1) || secp256k1_fe_is_zero(&r2));
    }
}

/* Test field inverse */
static void fuzz_field_inverse(const uint8_t *data, size_t size) {
    if (size >= 42) {     
        secp256k1_fe a, r1, r2, r3, zero;
        fuzz_field_construct(data, 0, 8, &a);
        secp256k1_fe_inv(&r1, &a);
        if (secp256k1_fe_normalizes_to_zero(&a)) {
            CHECK(secp256k1_fe_normalizes_to_zero(&r1));
        }
        else {
            CHECK(r1.magnitude == (a.magnitude != 0));
            CHECK(r1.normalized == 1);
            secp256k1_fe_mul(&r2, &a, &r1);
            secp256k1_fe_clear(&zero);
            secp256k1_fe_add_int(&zero, 1);
            secp256k1_fe_negate(&zero, &zero, 1);
            secp256k1_fe_add(&r2, &zero);
            CHECK(secp256k1_fe_normalizes_to_zero(&r2));
        }
    }
}

/* Test conditional move of field elements */
static void fuzz_field_cmov(const uint8_t *data, size_t size) {
    if (size >= 85) {        
        secp256k1_fe a, b, r1;
        fuzz_field_construct(data, 0, 32, &a);
        fuzz_field_construct(data + 42, 0, 32, &b);
        int flag = data[84] % 2;
        r1 = a;
        secp256k1_fe_cmov(&r1, &b, flag);
        CHECK((r1.magnitude == a.magnitude) || (r1.magnitude == b.magnitude));
        CHECK((r1.magnitude >= a.magnitude) && (r1.magnitude >= b.magnitude));
        CHECK(r1.normalized == (a.normalized && b.normalized));
        if (flag) {                        
            secp256k1_fe_normalize(&r1); 
            secp256k1_fe_normalize(&b);
            CHECK(secp256k1_fe_cmp_var(&r1, &b) == 0);
        } else {
            secp256k1_fe_normalize(&r1); 
            secp256k1_fe_normalize(&a);
            CHECK(secp256k1_fe_cmp_var(&r1, &a) == 0);
        }
    }
}

/* Test conditional move of fe_storage */
static void fuzz_field_storage_cmov(const uint8_t *data, size_t size) {
    if (size >= 85) {        
        secp256k1_fe a, b;
        secp256k1_fe_storage as, bs, rs1;
        fuzz_field_construct(data, 1, 1, &a);
        fuzz_field_construct(data + 42, 1, 1, &b);
        secp256k1_fe_to_storage(&as, &a);
        secp256k1_fe_to_storage(&bs, &b);
        int flag = data[84] % 2;
        rs1 = as;
        secp256k1_fe_storage_cmov(&rs1, &bs, flag);
        if (flag) {            
            CHECK(secp256k1_memcmp_var(&rs1, &bs, 32) == 0);
        } else {
            CHECK(secp256k1_memcmp_var(&rs1, &as, 32) == 0);
        }
    }
}

/* Test the operation of seting magnitude m to a field element. */
static void fuzz_field_get_bounds(const uint8_t *data, size_t size) {
    if (size >= 43) {
        secp256k1_fe a, b;    
        fuzz_field_construct(data, 0, 32, &a);
        int m = data[42] % 33;
        secp256k1_fe_get_bounds(&a,m);
        if (m == 0) {
            CHECK(a.normalized == 1);
        } else {
            CHECK(a.magnitude == m);
        }
    }
}


/*** Group Operation ***/
/** Construct a valid group element (on the curve) using 44 bytes data from fuzzer.  
*
* On input, 'data' must have 44 bytes at least. 
* On output, if function returns 1, a valid group element (on the curve) r is generated; Otherwise, return 0.
**/
static int fuzz_ge_construct(const uint8_t *data, secp256k1_ge *r) {
    secp256k1_fe x, x2, x3, y, z;
    secp256k1_ge ge;
    fuzz_field_construct(data, 0, 4, &x);
    if (secp256k1_ge_x_on_curve_var(&x)) {
        secp256k1_fe_sqr(&x2, &x);
        secp256k1_fe_mul(&x3, &x, &x2);
        secp256k1_fe_add_int(&x3, 7);
        secp256k1_fe_sqrt(&y, &x3);   
        /* result y has magnitude 1 and normalized 0 */
        int y_magnitude = 1 + data[42] % 3;
        int y_normalized = y_magnitude == 1 ? data[43] % 2 : 0;        
        if (y_normalized) {
            secp256k1_fe_normalize(&y);
        } else {
            secp256k1_fe_clear(&z);
            secp256k1_fe_negate(&z, &z, 0);
            secp256k1_fe_mul_int_unchecked(&z, y_magnitude - 1);
            /* change the magnitude of y without changing the field value by adding a 0 field element with (y_magnitude - 1) magnitude */
            secp256k1_fe_add(&y, &z);
        }
        ge.x = x;
        ge.y = y;
        ge.infinity = 0;  
        CHECK(secp256k1_ge_is_valid_var(&ge));
        CHECK(ge.y.magnitude == y_magnitude);
        *r = ge;
        return 1;
    } else {
        return 0;
    }
}

/* Check two group elements (affine) for equality */
static void fuzz_ge_equal(const secp256k1_ge *a, const secp256k1_ge *b) {
    CHECK(a->infinity == b->infinity);
    if (a->infinity) {
        return;
    }
    CHECK(secp256k1_fe_equal(&a->x, &b->x));
    CHECK(secp256k1_fe_equal(&a->y, &b->y));
}

/* Test transformation of group element between the affine coordinates and jacobian coordinates */
static void fuzz_ge_gej(const uint8_t *data, size_t size) {
    if (size>=84) {
        secp256k1_fe x, y, zr, xr, yr;
        secp256k1_ge ge, ge2;
        secp256k1_gej gej;
        /* construct a group element no matter whether it's on the curve */
        fuzz_field_construct(data, 0, 4, &x);
        fuzz_field_construct(data + 42, 0, 3, &y);
        secp256k1_ge_set_xy(&ge, &x, &y);
        secp256k1_gej_set_ge(&gej, &ge);
        /* Check ge.x * gej.z^2 == gej.x && ge.y * gej.z^3 == gej.y */
        secp256k1_fe_sqr(&zr, &gej.z);
        secp256k1_fe_mul(&xr, &ge.x, &zr);
        secp256k1_fe_mul(&zr, &zr, &gej.z);
        secp256k1_fe_mul(&yr, &ge.y, &zr);
        CHECK(ge.infinity == gej.infinity);
        CHECK(secp256k1_fe_equal(&xr, &gej.x));
        CHECK(secp256k1_fe_equal(&yr, &gej.y));        
        secp256k1_ge_set_gej(&ge2, &gej);
        fuzz_ge_equal(&ge2, &ge);                
    }
}

/* Test the validity and Z of result from point addition (gej + gej) on valid group elements with jacobian coordinates */
static void fuzz_gej_add_valid(const uint8_t *data, size_t size) {
    if (size >= 130) {
        secp256k1_fe zr1, zr2;
        secp256k1_ge ge1, ge2, ger1;
        secp256k1_gej a, b, r1;
        /* construct two group elements on the curve */
        if (fuzz_ge_construct(data, &ge1) && fuzz_ge_construct(data + 44, &ge2)) {                   
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &ge2);
            fuzz_field_construct(data + 88, 0, 32, &zr1);
            secp256k1_gej_add_var(&r1, &a, &b, &zr1);
            /* Check r->z == a->z * rz1 */
            secp256k1_fe_mul(&zr2, &zr1, &a.z);
            CHECK(secp256k1_fe_equal(&zr2, &r1.z)); 
            secp256k1_ge_set_gej_var(&ger1, &r1);
            if (ger1.infinity == 0){
                /* Check the result of point additin on valid ge is also on the curve (if result is not the point at infinity) */           
                CHECK(secp256k1_ge_is_valid_var(&ger1));
            }
        }  
    }
}

/* Test the equality of two group elements in jacobian coordinates */
static void fuzz_gej_eq(const uint8_t *data, size_t size) {
    if (size >= 44) {
        secp256k1_ge ge1, ge2;
        secp256k1_gej a, b, r1;
        /* construct valid group element */
        if (fuzz_ge_construct(data, &ge1)) {
            secp256k1_gej_set_ge(&a, &ge1);
            b = a;
            CHECK(secp256k1_gej_eq_var(&a, &b));
            secp256k1_fe_normalize(&b.x); 
            secp256k1_fe_add_int(&b.x, 1);
            CHECK(secp256k1_gej_eq_var(&a, &b)==0);
            b.infinity = 1;
            CHECK(secp256k1_gej_eq_var(&a, &b)==0);
            a.infinity = 1;
            CHECK(secp256k1_gej_eq_var(&a, &b));                               
        }  
    }
}

/* Test the equality of two group elements in jacobian coordinates using rescale */
static void fuzz_gej_recale(const uint8_t *data, size_t size) {
    if (size >= 86) {
        secp256k1_fe fe;
        secp256k1_ge ge1, ge2;
        secp256k1_gej a, b, r1;
        /* construct valid group element */
        if (fuzz_ge_construct(data, &ge1)) {
            secp256k1_gej_set_ge(&a, &ge1);
            b = a;
            fuzz_field_construct(data + 44, 0, 32, &fe);
            if (secp256k1_fe_normalizes_to_zero(&fe) || (fe.magnitude >=9)) {
                return;
            }
            secp256k1_gej_rescale(&b, &fe);
            CHECK(secp256k1_gej_eq_var(&a, &b));                             
        }  
    }
}

/* Test commutativity of point addition (gej + gej) on group elements with jacobian coordinates */
static void fuzz_gej_add_commutativity(const uint8_t *data, size_t size) {
    if (size >= 130) {
        secp256k1_fe zr;
        secp256k1_ge ge1, ge2, ger1, ger2;
        secp256k1_gej a, b, r1, r2;
        /* construct two valid group elements */
        if (fuzz_ge_construct(data, &ge1) && fuzz_ge_construct(data + 44, &ge2)) {                  
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &ge2);
            fuzz_field_construct(data + 88, 0, 32, &zr);
            /* check a + b == b + a */
            secp256k1_gej_add_var(&r1, &a, &b, &zr);
            secp256k1_gej_add_var(&r2, &b, &a, &zr);
            secp256k1_ge_set_gej(&ger1, &r1);
            secp256k1_ge_set_gej(&ger2, &r2);
            fuzz_ge_equal(&ger1, &ger2);
        }    
    }
}

/* Test associativity of point addition (gej + gej) on group elements with jacobian coordinates */
static void fuzz_gej_add_associativity(const uint8_t *data, size_t size) {
    if (size >= 216) {
        secp256k1_fe zr1, zr2;
        secp256k1_ge ge1, ge2, ge3, ger1, ger2;
        secp256k1_gej a, b, c, r1, r2;
        /* construct three valid group elements */
        if (fuzz_ge_construct(data, &ge1) && fuzz_ge_construct(data + 44, &ge2) && fuzz_ge_construct(data + 88, &ge3)) {
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &ge2);
            secp256k1_gej_set_ge(&c, &ge3);
            fuzz_field_construct(data + 132, 0, 32, &zr1);
            fuzz_field_construct(data + 174, 0, 32, &zr2);
            /* check a + b + c ==  a + (b + c) */
            secp256k1_gej_add_var(&r1, &a, &b, &zr1);
            secp256k1_gej_add_var(&r1, &r1, &c, secp256k1_gej_is_infinity(&r1) ? NULL : &zr2);
            secp256k1_gej_add_var(&r2, &b, &c, &zr2);
            secp256k1_gej_add_var(&r2, &r2, &a, secp256k1_gej_is_infinity(&r2) ? NULL : &zr1);    
            secp256k1_ge_set_gej(&ger1, &r1);
            secp256k1_ge_set_gej(&ger2, &r2);
            fuzz_ge_equal(&ger1, &ger2);
        }         
    }
} 

/* Test point addition (gej + gej) with a point at infinity */
static void fuzz_gej_add_infinity(const uint8_t *data, size_t size) {
    if (size >= 44) {
        secp256k1_ge ge1, infinity, ger1;
        secp256k1_gej a, b, r1;
        /* construct valid group element */
        if (fuzz_ge_construct(data, &ge1)) {  
            secp256k1_ge_set_infinity(&infinity);
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &infinity);
            secp256k1_gej_add_var(&r1, &b, &a, NULL);
            secp256k1_ge_set_gej(&ger1, &r1);
            fuzz_ge_equal(&ger1, &ge1);
        }             
    }
}

/* Test point addition (gej + gej) with opposites */
static void fuzz_gej_add_negate(const uint8_t *data, size_t size) {
    if (size >= 86) {
        secp256k1_fe zr;
        secp256k1_ge ge1, neg, ger1;
        secp256k1_gej a, b, r1;
        /* construct valid group element */
        if (fuzz_ge_construct(data, &ge1)) { 
            secp256k1_ge_neg(&neg, &ge1);
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &neg);
            fuzz_field_construct(data + 44, 0, 32, &zr);
            secp256k1_gej_add_var(&r1, &a, &b, &zr);
            secp256k1_ge_set_gej(&ger1, &r1);
            CHECK(secp256k1_ge_is_infinity(&ger1)); 
        }         
    }
} 

/* Test the validity of result from point doubling on group elements (constant time) */
static void fuzz_gej_double(const uint8_t *data, size_t size) {
    if (size >= 44) {
        secp256k1_ge ge1, ge2, ger1, ger2;
        secp256k1_gej a, b, r1, r2;
        /* construct valid group element */
        if (fuzz_ge_construct(data, &ge1)) { 
            ge2 = ge1;
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &ge2);
            secp256k1_gej_double(&r1, &a);
            secp256k1_gej_add_var(&r2, &a, &b, NULL);
            secp256k1_ge_set_gej(&ger1, &r1);
            CHECK(secp256k1_ge_is_valid_var(&ger1));
            secp256k1_ge_set_gej(&ger2, &r2);
            fuzz_ge_equal(&ger1, &ger2);
        }            
    }
}

/* Test the validity and Z of result from point doubling on group elements */
static void fuzz_gej_double_var(const uint8_t *data, size_t size) {
    if (size >= 86) {
        secp256k1_fe zr1, zr2;
        secp256k1_ge ge1, ge2, ger1, ger2;
        secp256k1_gej a, b, r1, r2;
        /* construct valid group element */
        if (fuzz_ge_construct(data, &ge1)) { 
            ge2 = ge1;
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &ge2);
            fuzz_field_construct(data + 44, 0, 32, &zr1);            
            secp256k1_gej_double_var(&r1, &a, &zr1);
            secp256k1_gej_add_var(&r2, &a, &b, &zr1);
            /* Check r->z == a->z * zr1 */
            secp256k1_fe_mul(&zr2, &zr1, &a.z);
            CHECK(secp256k1_fe_equal(&zr2, &r1.z)); 
            secp256k1_ge_set_gej(&ger1, &r1);
            CHECK(secp256k1_ge_is_valid_var(&ger1));
            secp256k1_ge_set_gej(&ger2, &r2);
            fuzz_ge_equal(&ger1, &ger2);
        }            
    }
}

/* Test the validity of result from point addition (gej + ge) on group elements (constant time) */
static void fuzz_gej_add_ge_valid(const uint8_t *data, size_t size) {
    if (size >= 88) {
        secp256k1_ge ge1, ge2, ger1, ger2;
        secp256k1_gej a, b, r1, r2;
        if (fuzz_ge_construct(data, &ge1) && fuzz_ge_construct(data + 44, &ge2)) {                    
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &ge2);
            secp256k1_gej_add_var(&r1, &a, &b, NULL);
            secp256k1_gej_add_ge(&r2, &a, &ge2);
            secp256k1_ge_set_gej(&ger1, &r1);           
            secp256k1_ge_set_gej(&ger2, &r2);
            fuzz_ge_equal(&ger1, &ger2);
            if (ger2.infinity == 0){
                /* Check the result of point additin on valid ge is also on the curve (if result is not the point at infinity) */           
                CHECK(secp256k1_ge_is_valid_var(&ger2));
            }            
        }  
    }
}

/* Test the validity of result from point addition (gej + ge) on group elements */
static void fuzz_gej_add_ge_var_valid(const uint8_t *data, size_t size) {
  if (size >= 130) {
        secp256k1_fe zr1, zr2;
        secp256k1_ge ge1, ge2, ger1, ger2;
        secp256k1_gej a, b, r1, r2;
        if (fuzz_ge_construct(data, &ge1) && fuzz_ge_construct(data + 44, &ge2)) {
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &ge2);
            fuzz_field_construct(data + 88, 0, 32, &zr1); 
            secp256k1_gej_add_var(&r1, &a, &b, &zr1);
            secp256k1_gej_add_ge_var(&r2, &a, &ge2, &zr1);
            /* Check r->z == a->z * zr1 */
            secp256k1_fe_mul(&zr2, &zr1, &a.z);
            CHECK(secp256k1_fe_equal(&zr2, &r2.z)); 
            secp256k1_ge_set_gej(&ger1, &r1);           
            secp256k1_ge_set_gej(&ger2, &r2);
            fuzz_ge_equal(&ger1, &ger2);
            if (ger2.infinity == 0){
                /* Check the result of point additin on valid ge is also on the curve (if result is not the point at infinity) */           
                CHECK(secp256k1_ge_is_valid_var(&ger2));
            }     
        }            
    }
}

/* Test point addition (gej + ge) with a point at infinity */
static void fuzz_gej_add_ge_infinity(const uint8_t *data, size_t size) {
    if (size >= 44) {
        secp256k1_ge ge1, infinity, ger1, ger2;
        secp256k1_gej a, b, r1, r2;
        /* construct valid group element */
        if (fuzz_ge_construct(data, &ge1)) { 
            secp256k1_ge_set_infinity(&infinity);
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &infinity);
            secp256k1_gej_add_ge(&r1, &b, &ge1);
            secp256k1_gej_add_ge_var(&r2, &b, &ge1, NULL);
            secp256k1_ge_set_gej(&ger1, &r1);
            secp256k1_ge_set_gej(&ger2, &r2);
            fuzz_ge_equal(&ger1, &ge1);
            fuzz_ge_equal(&ger2, &ge1);
        }             
    }
}

/* Test point addition (gej + ge) with opposites */
static void fuzz_gej_add_ge_negate(const uint8_t *data, size_t size) {
    if (size >= 86) {
        secp256k1_fe zr;
        secp256k1_ge ge1, neg, ger1, ger2;
        secp256k1_gej a, b, r1, r2;
        if (fuzz_ge_construct(data, &ge1)) { 
            secp256k1_ge_neg(&neg, &ge1);
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &neg);
            fuzz_field_construct(data + 44, 0, 32, &zr);
            secp256k1_gej_add_ge(&r1, &b, &ge1);
            secp256k1_gej_add_ge_var(&r2, &b, &ge1, &zr);
            secp256k1_ge_set_gej(&ger1, &r1);
            secp256k1_ge_set_gej(&ger2, &r2);
            CHECK(secp256k1_ge_is_infinity(&ger1)); 
            CHECK(secp256k1_ge_is_infinity(&ger2)); 
        }         
    }
}

/* Test point addition (gej + ge) with the inverse of ge's z coordinate  */
static void fuzz_gej_add_zinv_var(const uint8_t *data, size_t size) {
    if (size >= 130) {
        secp256k1_fe zr, zrx, zry;
        secp256k1_ge ge1, ge2, ge3, ger1, ger2;
        secp256k1_gej a, b, c, r1, r2;
        if (fuzz_ge_construct(data, &ge1) && fuzz_ge_construct(data + 44, &ge2)) { 
            ge3 = ge2;
            fuzz_field_construct(data + 88, 1, 1, &zr);
            if (secp256k1_fe_is_zero(&zr)) {
                return;
            }
            /* compute zrx = 1/(zr^2), zry = 1/(zf^3) */
            secp256k1_fe_inv_var(&zry, &zr);
            secp256k1_fe_sqr(&zrx, &zry);
            secp256k1_fe_mul(&zry, &zry, &zrx);
            /* rescale the ge3.x and ge3.y */
            secp256k1_fe_mul(&ge3.x, &ge3.x, &zrx);
            secp256k1_fe_mul(&ge3.y, &ge3.y, &zry);
            secp256k1_gej_set_ge(&a, &ge1);
            secp256k1_gej_set_ge(&b, &ge2);            
            secp256k1_gej_add_zinv_var(&r1, &a, &ge3, &zr);
            secp256k1_gej_add_var(&r2, &a, &b, &zr);
            secp256k1_ge_set_gej(&ger1, &r1);
            secp256k1_ge_set_gej(&ger2, &r2);
            fuzz_ge_equal(&ger1, &ger2);
        }         
    }
}
/* Test the fraction xn/xd is a valid X coordinate on the curve */
static void fuzz_ge_x_frac_on_curve_var(const uint8_t *data, size_t size) {
    if (size >= 86) {
        secp256k1_fe zr, zrx;
        secp256k1_ge ge1, ge2, ger1, ger2;
        secp256k1_gej a, b, r1, r2;
        if (fuzz_ge_construct(data, &ge1)) {
            fuzz_field_construct(data + 44, 1, 1, &zr);
            if (secp256k1_fe_is_zero(&zr)) {
                return;
            }
            secp256k1_fe_mul(&zrx, &zr, &ge1.x);
            CHECK(secp256k1_ge_x_frac_on_curve_var(&zrx, &zr)); 
        }             
    }
}

/* Test conditional move of gej */
static void fuzz_gej_cmov(const uint8_t *data, size_t size) {
    if (size >= 169) {        
        secp256k1_fe x1, x2, y1, y2;
        secp256k1_ge ge1, ge2;
        secp256k1_gej a, b, r1;
        /* construct two group elements no matter whether it's on the curve */ 
        fuzz_field_construct(data, 0, 4, &x1);
        fuzz_field_construct(data + 42, 0, 3, &y1);
        secp256k1_ge_set_xy(&ge1, &x1, &y1);
        fuzz_field_construct(data + 84, 0, 4, &x2);
        fuzz_field_construct(data + 126, 0, 3, &y2);
        secp256k1_ge_set_xy(&ge2, &x2, &y2);
        secp256k1_gej_set_ge(&a, &ge1);
        secp256k1_gej_set_ge(&b, &ge2);
        int flag = data[168] % 2;
        r1 = a;
        secp256k1_gej_cmov(&r1, &b, flag);
        secp256k1_fe_normalize(&r1.x);
        secp256k1_fe_normalize(&r1.y);  
        if (flag) {
            CHECK(r1.infinity == b.infinity);                        
            CHECK(secp256k1_fe_equal(&r1.x, &b.x));
            CHECK(secp256k1_fe_equal(&r1.y, &b.y));
            CHECK(secp256k1_fe_equal(&r1.z, &b.z));
        } else {
            CHECK(r1.infinity == a.infinity);
            CHECK(secp256k1_fe_equal(&r1.x, &a.x));
            CHECK(secp256k1_fe_equal(&r1.y, &a.y));
            CHECK(secp256k1_fe_equal(&r1.z, &b.z));
        }
    }
}

/* Test conversions between group element and secp256k1_ge_storage */ 
static void fuzz_ge_and_storage(const uint8_t *data, size_t size) {
    if (size >= 84) {
        secp256k1_fe x, y;
        secp256k1_ge ge1, ge2;
        secp256k1_ge_storage ges;
        /* construct a group element no matter whether it's on the curve */ 
        fuzz_field_construct(data, 0, 4, &x);
        fuzz_field_construct(data + 42, 0, 3, &y);
        secp256k1_ge_set_xy(&ge1, &x, &y);
        secp256k1_ge_to_storage(&ges, &ge1);
        secp256k1_ge_from_storage(&ge2, &ges);
        fuzz_ge_equal(&ge2, &ge1);
    }
}

/* Test conditional move of ge_storage */
static void fuzz_ge_storage_cmov(const uint8_t *data, size_t size) {
    if (size >= 169) {        
        secp256k1_fe x1, x2, y1, y2;
        secp256k1_ge ge1, ge2;
        secp256k1_ge_storage ges1, ges2, rs1; 
        fuzz_field_construct(data, 0, 4, &x1);
        fuzz_field_construct(data + 42, 0, 3, &y1);
        secp256k1_ge_set_xy(&ge1, &x1, &y1);
        fuzz_field_construct(data + 84, 0, 4, &x2);
        fuzz_field_construct(data + 126, 0, 3, &y2);
        secp256k1_ge_set_xy(&ge2, &x2, &y2);
        secp256k1_ge_to_storage(&ges1, &ge1);
        secp256k1_ge_to_storage(&ges2, &ge2);
        int flag = data[168] % 2;
        rs1 = ges1;
        secp256k1_ge_storage_cmov(&rs1, &ges2, flag);
        if (flag) {            
            CHECK(secp256k1_memcmp_var(&rs1.x, &ges2.x, 32) == 0);
            CHECK(secp256k1_memcmp_var(&rs1.y, &ges2.y, 32) == 0);
        } else {
            CHECK(secp256k1_memcmp_var(&rs1.x, &ges1.x, 32) == 0);
            CHECK(secp256k1_memcmp_var(&rs1.y, &ges1.y, 32) == 0);
        }
    }
}

typedef void (*fuzz_function)(const uint8_t* data, size_t size);

static fuzz_function selected_fuzz_function = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const char* test_name = getenv("FUZZ");
    if (!test_name) {
        fprintf(stderr, "Select a fuzz test using the FUZZ environment variable\n");
        assert(0);
    }
    if (strcmp(test_name, "scalar_add_commutativty") == 0) {
        selected_fuzz_function = &fuzz_scalar_add_commutativty;
    } else if (strcmp(test_name, "scalar_add_associativity") == 0) {
        selected_fuzz_function = &fuzz_scalar_add_associativity;
    } else if (strcmp(test_name, "scalar_add_zero") == 0) {
        selected_fuzz_function = &fuzz_scalar_add_zero;
    } else if (strcmp(test_name, "scalar_add_complements") == 0) {
        selected_fuzz_function = &fuzz_scalar_add_complements;
    } else if (strcmp(test_name, "scalar_mul_commutativity") == 0) {
        selected_fuzz_function = &fuzz_scalar_mul_commutativity;
    } else if (strcmp(test_name, "scalar_mul_associativity") == 0) {
        selected_fuzz_function = &fuzz_scalar_mul_associativity;
    } else if (strcmp(test_name, "scalar_mul_distributivity") == 0) {
        selected_fuzz_function = &fuzz_scalar_mul_distributivity;
    } else if (strcmp(test_name, "scalar_mul_one") == 0) {
        selected_fuzz_function = &fuzz_scalar_mul_one;
    } else if (strcmp(test_name, "scalar_mul_zero") == 0) {
        selected_fuzz_function = &fuzz_scalar_mul_zero;
    } else if (strcmp(test_name, "scalar_inverse") == 0) {
        selected_fuzz_function = &fuzz_scalar_inverse;
    } else if (strcmp(test_name, "scalar_inverse_var") == 0) {
        selected_fuzz_function = &fuzz_scalar_inverse_var;
    } else if (strcmp(test_name, "scalar_negate") == 0) {
        selected_fuzz_function = &fuzz_scalar_negate;
    } else if (strcmp(test_name, "scalar_shift") == 0) {
        selected_fuzz_function = &fuzz_scalar_shift;
    } else if (strcmp(test_name, "scalar_split_lambda") == 0) {
        selected_fuzz_function = &fuzz_scalar_split_lambda;
    } else if (strcmp(test_name, "scalar_cmov") == 0) {
        selected_fuzz_function = &fuzz_scalar_cmov;
    } else if (strcmp(test_name, "field_comparison") == 0) {
        selected_fuzz_function = &fuzz_field_comparison;
    } else if (strcmp(test_name, "field_equal") == 0) {
        selected_fuzz_function = &fuzz_field_equal;
    } else if (strcmp(test_name, "field_b32_and_fe") == 0) {
        selected_fuzz_function = &fuzz_field_b32_and_fe;
    } else if (strcmp(test_name, "field_fe_and_storage") == 0) {
        selected_fuzz_function = &fuzz_field_fe_and_storage;
    } else if (strcmp(test_name, "field_add_commutativity") == 0) {
        selected_fuzz_function = &fuzz_field_add_commutativity;
    } else if (strcmp(test_name, "field_add_associativity") == 0) {
        selected_fuzz_function = &fuzz_field_add_associativity;
    } else if (strcmp(test_name, "field_add_zero") == 0) {
        selected_fuzz_function = &fuzz_field_add_zero;
    } else if (strcmp(test_name, "field_add_negate") == 0) {
        selected_fuzz_function = &fuzz_field_add_negate;
    } else if (strcmp(test_name, "field_add_negate_unchecked") == 0) {
        selected_fuzz_function = &fuzz_field_add_negate_unchecked;
    } else if (strcmp(test_name, "field_add_integer") == 0) {
        selected_fuzz_function = &fuzz_field_add_integer;
    } else if (strcmp(test_name, "field_half") == 0) {
        selected_fuzz_function = &fuzz_field_half;
    } else if (strcmp(test_name, "field_mul_commutativity") == 0) {
        selected_fuzz_function = &fuzz_field_mul_commutativity;
    } else if (strcmp(test_name, "field_mul_associativity") == 0) {
        selected_fuzz_function = &fuzz_field_mul_associativity;
    } else if (strcmp(test_name, "field_mul_distributivity") == 0) {
        selected_fuzz_function = &fuzz_field_mul_distributivity;
    } else if (strcmp(test_name, "field_mul_zero") == 0) {
        selected_fuzz_function = &fuzz_field_mul_zero;
    } else if (strcmp(test_name, "field_mul_integer") == 0) {
        selected_fuzz_function = &fuzz_field_mul_integer;
    } else if (strcmp(test_name, "field_sqr") == 0) {
        selected_fuzz_function = &fuzz_field_sqr;
    } else if (strcmp(test_name, "field_sqrt") == 0) {
        selected_fuzz_function = &fuzz_field_sqrt;
    } else if (strcmp(test_name, "field_inverse") == 0) {
        selected_fuzz_function = &fuzz_field_inverse;
    } else if (strcmp(test_name, "field_cmov") == 0) {
        selected_fuzz_function = &fuzz_field_cmov;
    } else if (strcmp(test_name, "field_storage_cmov") == 0) {
        selected_fuzz_function = &fuzz_field_storage_cmov;
    } else if (strcmp(test_name, "field_get_bounds") == 0) {
        selected_fuzz_function = &fuzz_field_get_bounds;
    } else if (strcmp(test_name, "group_ge_gej") == 0) {
        selected_fuzz_function = &fuzz_ge_gej;
    } else if (strcmp(test_name, "group_gej_add_valid") == 0) {
        selected_fuzz_function = &fuzz_gej_add_valid;
    } else if (strcmp(test_name, "group_gej_eq") == 0) {
        selected_fuzz_function = &fuzz_gej_eq;
    } else if (strcmp(test_name, "group_gej_recale") == 0) {
        selected_fuzz_function = &fuzz_gej_recale;
    } else if (strcmp(test_name, "group_gej_add_commutativity") == 0) {
        selected_fuzz_function = &fuzz_gej_add_commutativity;
    } else if (strcmp(test_name, "group_gej_add_associativity") == 0) {
        selected_fuzz_function = &fuzz_gej_add_associativity;
    } else if (strcmp(test_name, "group_gej_add_infinity") == 0) {
        selected_fuzz_function = &fuzz_gej_add_infinity;       
    } else if (strcmp(test_name, "group_gej_add_negate") == 0) {
        selected_fuzz_function = &fuzz_gej_add_negate;
    } else if (strcmp(test_name, "group_gej_double") == 0) {
        selected_fuzz_function = &fuzz_gej_double;
    } else if (strcmp(test_name, "group_gej_double_var") == 0) {
        selected_fuzz_function = &fuzz_gej_double_var;
    } else if (strcmp(test_name, "group_gej_add_ge_valid") == 0) {
        selected_fuzz_function = &fuzz_gej_add_ge_valid;
    } else if (strcmp(test_name, "group_gej_add_ge_var_valid") == 0) {
        selected_fuzz_function = &fuzz_gej_add_ge_var_valid;
    } else if (strcmp(test_name, "group_gej_add_ge_infinity") == 0) {
        selected_fuzz_function = &fuzz_gej_add_ge_infinity;
    } else if (strcmp(test_name, "group_gej_add_ge_negate") == 0) {
        selected_fuzz_function = &fuzz_gej_add_ge_negate;
    } else if (strcmp(test_name, "group_gej_add_zinv_var") == 0) {
        selected_fuzz_function = &fuzz_gej_add_zinv_var;
    } else if (strcmp(test_name, "group_ge_x_frac_on_curve_var") == 0) {
        selected_fuzz_function = &fuzz_ge_x_frac_on_curve_var;
    } else if (strcmp(test_name, "group_gej_cmov") == 0) {
        selected_fuzz_function = &fuzz_gej_cmov;
    } else if (strcmp(test_name, "group_ge_and_storage") == 0) {
        selected_fuzz_function = &fuzz_ge_and_storage;       
    } else if (strcmp(test_name, "group_ge_storage_cmov") == 0) {
        selected_fuzz_function = &fuzz_ge_storage_cmov;
    } else {
        fprintf(stderr, "Unknown fuzz test selected using FUZZ environment variable: %s\n", test_name);
        assert(0);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    selected_fuzz_function(data, size);
    return 0;
}
       