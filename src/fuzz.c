#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>

#include "scalar_impl.h"
#include "field_impl.h"
#include "group_impl.h"
#include "ecmult_impl.h"
#include "ecmult_const_impl.h"
#include "ecmult_gen_impl.h"
#include "int128_impl.h"
#include "scratch_impl.h"
#include "testrand_impl.h"

/*** Scalar Operation ***/

/* Test commutativity of scalar addition */ 
static void fuzz_commutate_add(const uint8_t *data, size_t size) {
    if (size > 63) {        
        secp256k1_scalar a, b,r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_set_b32(&b, data + 32, NULL);
        secp256k1_scalar_add(&r1, &a, &b);
        secp256k1_scalar_add(&r2, &b, &a);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }
}

/* Test associativity of scalar addition */
static void fuzz_associate_add(const uint8_t *data, size_t size) {
    if (size > 95) {     
        secp256k1_scalar a, b, c,r1, r2;
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
static void fuzz_zero_add(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_scalar a,r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_add(&r1, &a, &secp256k1_scalar_zero);
        CHECK(secp256k1_scalar_eq(&r1, &a));
    }
}

/* Test scalar addition with its complement */ 
static void fuzz_complement_add(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_scalar a,r1,r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_negate(&r1, &a);
        secp256k1_scalar_add(&r2, &a, &r1);
        CHECK(secp256k1_scalar_is_zero(&r2));
    }
}

/* Test commutativity of scalar multiplication */
static void fuzz_commutate_mul(const uint8_t *data, size_t size) {
    if (size > 63) {        
        secp256k1_scalar a, b,r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_set_b32(&b, data + 32, NULL);
        secp256k1_scalar_mul(&r1, &a, &b);
        secp256k1_scalar_mul(&r2, &b, &a);
        CHECK(secp256k1_scalar_eq(&r1, &r2));
    }
}

/* Test associativity of scalar multiplication */
static void fuzz_associate_mul(const uint8_t *data, size_t size) {
    if (size > 95) {     
        secp256k1_scalar a, b, c,r1, r2;
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
static void fuzz_distri_mul(const uint8_t *data, size_t size) {
    if (size > 95) {     
        secp256k1_scalar a, b, c,r1, r2, r3;
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
static void fuzz_one_mul(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_scalar a,r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_mul(&r1, &a, &secp256k1_scalar_one);
        CHECK(secp256k1_scalar_eq(&r1, &a));
    }
}


/* Test scalar multiplication with zero */ 
static void fuzz_zero_mul(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_scalar a,r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_mul(&r1, &a, &secp256k1_scalar_zero);
        CHECK(secp256k1_scalar_is_zero(&r1));
    }
}

/* Test scalar inverse */
static void fuzz_scalar_inverse(const uint8_t *data, size_t size) {
    if (size > 31) {     
        secp256k1_scalar a,r1, r2, r3;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_inverse(&r1, &a);
        if (secp256k1_scalar_is_zero(&a)) {
            CHECK(secp256k1_scalar_is_zero(&r1));
        }
        else {
            secp256k1_scalar_mul(&r2, &a, &r1);
            CHECK(secp256k1_scalar_is_one(&r2));
        }
    }
} 

/* Test scalar inverse (without constant-time guarantee) */
static void fuzz_scalar_inverse_var(const uint8_t *data, size_t size) {
    if (size > 31) {     
        secp256k1_scalar a, r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_inverse_var(&r1, &a);
        if (secp256k1_scalar_is_zero(&a)) {
            CHECK(secp256k1_scalar_is_zero(&r1));
        }
        else {
            secp256k1_scalar_mul(&r2, &a, &r1);
            CHECK(secp256k1_scalar_is_one(&r2));
        }
    }
}             

/* Test scalar complement */ 
static void fuzz_scalar_negate(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_scalar a,r1,r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_negate(&r1, &a);
        secp256k1_scalar_negate(&r2, &r1);
        CHECK(secp256k1_scalar_eq(&a, &r2));
    }
}


/* Test low bits shifted off */
static void fuzz_scalar_shift(const uint8_t *data, size_t size) {
    if (size > 31) {
        int bit, r1, r2;     
        secp256k1_scalar a;
        secp256k1_scalar_set_b32(&a, data, NULL);
        bit = 1 + secp256k1_testrand_int(15);
        r2 = a.d[0] % (1ULL << bit);
        r1 = secp256k1_scalar_shr_int(&a, bit);
        CHECK(r1 == r2);
    }
}

/* Test r1+r2*lambda = a */
static void fuzz_scalar_splite_lambda(const uint8_t *data, size_t size) {
    if (size > 31) {
        secp256k1_scalar a, r1, r2, r3;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_split_lambda(&r1, &r2, &a);
        secp256k1_scalar_mul(&r3, &secp256k1_const_lambda, &r2);
        secp256k1_scalar_add(&r3, &r3, &r1);
        CHECK(secp256k1_scalar_eq(&r3, &a));
    }    
}        
   

/** Entry point of Libfuzzer **/  
/** 
int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    test(data,size);
    return 0;
}
**/   
        
        