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
/* Construct a valid field element from fuzzer with random magnitude  */
static void fuzz_field_construct(const uint8_t *data, size_t size, secp256k1_fe *r) {    
    if (size>=32) {
        secp256k1_fe a, zero;      
        secp256k1_fe_set_b32_mod(r, data);
        int rand_magnitude = data[31] % 33;
        secp256k1_fe_normalize(r);
        if (rand_magnitude == 0) {
            return;
        }
        secp256k1_fe_clear(&zero);
        secp256k1_fe_negate(&zero, &zero, 0);
        secp256k1_fe_mul_int_unchecked(&zero, rand_magnitude - 1);
        secp256k1_fe_add(r, &zero);         
    }
}

#ifdef VERIFY
/* Test the field element comparison operations. */
static void fuzz_field_comparison(const uint8_t *data, size_t size) {
    if (size >= 32) {
        secp256k1_fe a;    
        fuzz_field_construct(data, size, &a);
        if (a.normalized) { 
            CHECK(secp256k1_fe_cmp_var(&a, &a) == 0);
        }
    }
}

/* Test conversions between 32-byte value and field element */ 
static void fuzz_field_b32_and_fe(const uint8_t *data, size_t size) {
    if (size >= 32) {
        secp256k1_fe a, b;
        unsigned char b32[32];     
        fuzz_field_construct(data, size, &a);  
        if (!a.normalized) {
            return;
        }
        secp256k1_fe_get_b32(b32, &a);
        secp256k1_fe_set_b32_limit(&b, b32);
        CHECK(secp256k1_fe_cmp_var(&a, &b) == 0);       
    }
}

/* Test conversions between field element and secp256k1_fe_storage */ 
static void fuzz_field_fe_and_storage(const uint8_t *data, size_t size) {
    if (size >= 32) {
        secp256k1_fe a, b;
        secp256k1_fe_storage fes; 
        fuzz_field_construct(data, size, &a);
        if (!a.normalized) {
            return;
        }
        secp256k1_fe_to_storage(&fes, &a);
        secp256k1_fe_from_storage(&b, &fes);
        CHECK(secp256k1_fe_cmp_var(&a, &b) == 0);
    }
}

/* Test commutativity of addition on two field elements */ 
static void fuzz_field_add_commutativty(const uint8_t *data, size_t size) {
    if (size >= 64) {        
        secp256k1_fe a, b, r1, r2;
        fuzz_field_construct(data, size, &a);
        fuzz_field_construct(data + 32, size, &b);         
        if (a.magnitude + b.magnitude > 32) {
            return;
        }    
        r1 = a;
        secp256k1_fe_add(&r1, &b);
        r2 = b;
        secp256k1_fe_add(&r2, &a);    
        CHECK(r1.magnitude == a.magnitude + b.magnitude);
        CHECK(r2.magnitude == r1.magnitude);
        secp256k1_fe_normalize(&r1);
        secp256k1_fe_normalize(&r2);
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);
    }
}

/* Test associativity of addition on field elements */
static void fuzz_field_add_associativity(const uint8_t *data, size_t size) {
    if (size >= 96) {     
        secp256k1_fe a, b, c, r1, r2;
        fuzz_field_construct(data, size, &a);
        fuzz_field_construct(data + 32, size, &b);
        fuzz_field_construct(data + 64, size, &c);
        if (a.magnitude + b.magnitude + c.magnitude > 32) {
            return;
        }
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
        CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);
    }
}


/* Test identity addition on field elements */ 
static void fuzz_field_add_zero(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_fe a, zero, r1;
        fuzz_field_construct(data, size, &a);        
        secp256k1_fe_clear(&zero);
        r1 = a;
        secp256k1_fe_add(&r1, &zero);
        secp256k1_fe_normalize(&a);
        secp256k1_fe_normalize(&r1);
        CHECK(secp256k1_fe_cmp_var(&r1, &a) == 0);
    }
}

/* Test addition of field element and its negative value */ 
static void fuzz_field_add_negate(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_fe a, negate;
        fuzz_field_construct(data, size, &a);
        if (a.magnitude >= 32) {
            return;
        }
        secp256k1_fe_negate(&negate, &a, 31);
        CHECK(negate.magnitude == 32);
        secp256k1_fe_normalize(&a);
        secp256k1_fe_normalize(&negate);    
        secp256k1_fe_add(&a, &negate);
        CHECK(secp256k1_fe_normalizes_to_zero(&a));
    }
}

/* Test addition of field element and an integer */ 
static void fuzz_field_add_integer(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_fe a, r1, r2;
        int v = data[0];
        fuzz_field_construct(data, size, &a);
        secp256k1_fe_set_int(&r1, v);
        if (a.magnitude + r1.magnitude >= 32) {
            return;
        }
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
    if (size >= 32) {
        secp256k1_fe a, b;
        fuzz_field_construct(data, size, &a);
        if (a.magnitude < 32) {
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
}

/* Test commutativity of multiplication on two field elements */
static void fuzz_field_mul_commutativity(const uint8_t *data, size_t size) {
    if (size >= 64) {        
        secp256k1_fe a, b, r1, r2;
        fuzz_field_construct(data, size, &a);
        fuzz_field_construct(data + 32, size, &b);
        if ((a.magnitude <= 8) && (b.magnitude <= 8)) {
            secp256k1_fe_mul(&r1, &a, &b);
            secp256k1_fe_mul(&r2, &b, &a);
            CHECK((r1.magnitude == 1) && (r2.magnitude == 1));
            CHECK((r1.normalized == 0) && (r2.normalized == 0));
            secp256k1_fe_normalize(&r1);
            secp256k1_fe_normalize(&r2);
            CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);
        }        
    }
}

/* Test associativity of multiplication on field elements */
static void fuzz_field_mul_associativity(const uint8_t *data, size_t size) {
    if (size >= 96) {     
        secp256k1_fe a, b, c, r1, r2;
        fuzz_field_construct(data, size, &a);
        fuzz_field_construct(data + 32, size, &b);
        fuzz_field_construct(data + 64, size, &c);
        if ((a.magnitude <= 8) && (b.magnitude <= 8) && (c.magnitude <= 8)) {
            secp256k1_fe_mul(&r1, &a, &b);
            secp256k1_fe_mul(&r1, &r1, &c);
            secp256k1_fe_mul(&r2, &b, &c);
            secp256k1_fe_mul(&r2, &r2, &a);
            CHECK((r1.magnitude == 1) && (r2.magnitude == 1));
            CHECK((r1.normalized == 0) && (r2.normalized == 0));
            secp256k1_fe_normalize(&r1);
            secp256k1_fe_normalize(&r2);
            CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);;
        }
    }
}

/* Test distributivity of multiplication on field elements */
static void fuzz_field_mul_distributivity(const uint8_t *data, size_t size) {
    if (size >= 96) {     
        secp256k1_fe a, b, c, r1, r2, r3;
        fuzz_field_construct(data, size, &a);
        fuzz_field_construct(data + 32, size, &b);
        fuzz_field_construct(data + 64, size, &c);
        if ((a.magnitude <= 8) && (b.magnitude <= 8) && (c.magnitude <= 8)) {
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
            CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);;
        }
    }
}

/* Test field multiplication with 0 */ 
static void fuzz_field_mul_zero(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_fe a, zero, r1;
        fuzz_field_construct(data, size, &a);
        if (a.magnitude <= 8) {
            secp256k1_fe_clear(&zero);
            secp256k1_fe_mul(&r1, &a, &zero);
            CHECK(r1.magnitude == 1);
            CHECK(r1.normalized == 0);
            secp256k1_fe_normalize(&r1);
            CHECK(secp256k1_fe_is_zero(&r1));;
        }
    }
}

/* Test multiplication of field element with an integer */
static void fuzz_field_mul_integer(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_fe a, r1, r2;
        fuzz_field_construct(data, size, &a);
        if (a.magnitude <= 10) {
            int m = a.magnitude;
            r1 = a;
            secp256k1_fe_mul_int(&r1, 3);
            CHECK(r1.magnitude == m * 3);
            CHECK(r1.normalized == 0);
            r2 = a;
            secp256k1_fe_add(&r2, &a);
            secp256k1_fe_add(&r2, &a);
            secp256k1_fe_normalize(&r1);
            secp256k1_fe_normalize(&r2);
            CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);;
        }
    }
}

/* Test square of a field element */
static void fuzz_field_sqr(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_fe a, negate, r1, r2;
        fuzz_field_construct(data, size, &a);
        if (a.magnitude <= 8) {
            secp256k1_fe_sqr(&r1, &a);
            secp256k1_fe_negate(&negate, &a, 8);
            if (negate.magnitude >= 9) {
                return;          
            }
            secp256k1_fe_sqr(&r2, &negate);
            CHECK(r1.magnitude == 1);
            CHECK(r1.normalized == 0);
            CHECK(r2.magnitude == 1);
            CHECK(r2.normalized == 0);
            secp256k1_fe_normalize(&r1);
            secp256k1_fe_normalize(&r2);
            CHECK(secp256k1_fe_cmp_var(&r1, &r2) == 0);;
        } 
    }
}

/* Test square root of a field element */
static void fuzz_field_sqrt(const uint8_t *data, size_t size) {
    if (size >= 32) {        
        secp256k1_fe a, b, r1, r2;
        fuzz_field_construct(data, size, &a);
        if (a.magnitude >= 9) {
            secp256k1_fe_sqr(&b, &a);
            secp256k1_fe_sqrt(&r1, &b);
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
}

/* Test field inverse */
static void fuzz_field_inverse(const uint8_t *data, size_t size) {
    if (size >= 32) {     
        secp256k1_fe a, r1, r2, r3, zero;
        fuzz_field_construct(data, size, &a);
        secp256k1_fe_inv(&r1, &a);
        if (secp256k1_fe_normalizes_to_zero(&a)) {
            CHECK(secp256k1_fe_normalizes_to_zero(&r1));
        }
        else {
            CHECK(r1.magnitude == (a.magnitude != 0));
            CHECK(r1.normalized == 1);
            if (a.magnitude <= 8) {
                secp256k1_fe_mul(&r2, &a, &r1);
                secp256k1_fe_clear(&zero);
                secp256k1_fe_add_int(&zero, 1);
                secp256k1_fe_negate(&zero, &zero, 1);
                secp256k1_fe_add(&r2, &zero);
                CHECK(secp256k1_fe_normalizes_to_zero(&r2));
            }
        }
    }
}

/* Test conditional move of field elements */
static void fuzz_field_cmov(const uint8_t *data, size_t size) {
    if (size >= 64) {        
        secp256k1_fe a, b, r1;
        fuzz_field_construct(data, size, &a);
        fuzz_field_construct(data + 32, size, &b);
        int flag = data[63] % 2;
        r1 = a;
        if (flag) {            
            secp256k1_fe_cmov(&r1, &b, 1);
            CHECK((r1.magnitude == a.magnitude) || (r1.magnitude == b.magnitude));
            CHECK((r1.magnitude >= a.magnitude) && (r1.magnitude >= b.magnitude));
            CHECK(r1.normalized == (a.normalized && b.normalized));
            secp256k1_fe_normalize(&r1); 
            secp256k1_fe_normalize(&b);
            CHECK(secp256k1_fe_cmp_var(&r1, &b) == 0);
        } else {
            secp256k1_fe_cmov(&r1, &b, 0);
            CHECK((r1.magnitude == a.magnitude) || (r1.magnitude == b.magnitude));
            CHECK((r1.magnitude >= a.magnitude) && (r1.magnitude >= b.magnitude));
            CHECK(r1.normalized == (a.normalized && b.normalized));
            secp256k1_fe_normalize(&r1); 
            secp256k1_fe_normalize(&a);
            CHECK(secp256k1_fe_cmp_var(&r1, &a) == 0);
        }
    }
}

/* Test conditional move of fe_storage */
static void fuzz_field_storage_cmov(const uint8_t *data, size_t size) {
    if (size >= 64) {        
        secp256k1_fe a, b;
        secp256k1_fe_storage as, bs, rs1;
        fuzz_field_construct(data, size, &a);
        fuzz_field_construct(data + 32, size, &b);
        secp256k1_fe_normalize(&a); 
        secp256k1_fe_normalize(&b);
        secp256k1_fe_to_storage(&as, &a);
        secp256k1_fe_to_storage(&bs, &b);
        int flag = data[63] % 2;
        rs1 = as;
        if (flag) {            
            secp256k1_fe_storage_cmov(&rs1, &bs, 1);
            CHECK(secp256k1_memcmp_var(&rs1, &bs, 32) == 0);
        } else {
            secp256k1_fe_storage_cmov(&rs1, &bs, 0);
            CHECK(secp256k1_memcmp_var(&rs1, &as, 32) == 0);
        }
    }
}
#endif

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
    } else if (strcmp(test_name, "fuzz_field_comparison") == 0) {
        selected_fuzz_function = &fuzz_field_comparison;
    } else if (strcmp(test_name, "field_b32_and_fe") == 0) {
        selected_fuzz_function = &fuzz_field_b32_and_fe;
    } else if (strcmp(test_name, "field_fe_and_storage") == 0) {
        selected_fuzz_function = &fuzz_field_fe_and_storage;
    } else if (strcmp(test_name, "field_add_commutativty") == 0) {
        selected_fuzz_function = &fuzz_field_add_commutativty;
    } else if (strcmp(test_name, "field_add_associativity") == 0) {
        selected_fuzz_function = &fuzz_field_add_associativity;
    } else if (strcmp(test_name, "field_add_zero") == 0) {
        selected_fuzz_function = &fuzz_field_add_zero;
    } else if (strcmp(test_name, "field_add_negate") == 0) {
        selected_fuzz_function = &fuzz_field_add_negate;
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



        
        