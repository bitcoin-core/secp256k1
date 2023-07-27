#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <assert.h>
#include <stdbool.h>

#include "secp256k1.c"

/*** Scalar Operation ***/
/* Test commutativity of scalar addition */ 
static void fuzz_scalar_add_commutativty(const uint8_t *data, size_t size) {
    if (size > 63) {        
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
    if (size > 95) {     
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
    if (size > 31) {        
        secp256k1_scalar a, r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_add(&r1, &a, &secp256k1_scalar_zero);
        CHECK(secp256k1_scalar_eq(&r1, &a));
    }
}

/* Test scalar addition with its complement */ 
static void fuzz_scalar_add_complements(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_scalar a, r1, r2;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_negate(&r1, &a);
        secp256k1_scalar_add(&r2, &a, &r1);
        CHECK(secp256k1_scalar_is_zero(&r2));
    }
}

/* Test commutativity of scalar multiplication */
static void fuzz_scalar_mul_commutativity(const uint8_t *data, size_t size) {
    if (size > 63) {        
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
    if (size > 95) {     
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
    if (size > 95) {     
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
    if (size > 31) {        
        secp256k1_scalar a, r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_mul(&r1, &a, &secp256k1_scalar_one);
        CHECK(secp256k1_scalar_eq(&r1, &a));
    }
}

/* Test scalar multiplication with zero */ 
static void fuzz_scalar_mul_zero(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_scalar a, r1;
        secp256k1_scalar_set_b32(&a, data, NULL);
        secp256k1_scalar_mul(&r1, &a, &secp256k1_scalar_zero);
        CHECK(secp256k1_scalar_is_zero(&r1));
    }
}

/* Test scalar inverse */
static void fuzz_scalar_inverse(const uint8_t *data, size_t size) {
    if (size > 31) {     
        secp256k1_scalar a, r1, r2, r3;
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
        secp256k1_scalar a, r1, r2;
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
        bit = 1 + (size % 15);
        r2 = a.d[0] % (1ULL << bit);
        r1 = secp256k1_scalar_shr_int(&a, bit);
        CHECK(r1 == r2);
    }
}

/* Test r1+r2*lambda = a */
static void fuzz_scalar_split_lambda(const uint8_t *data, size_t size) {
    if (size > 31) {
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
    if (size > 63) {        
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
/* Test the field element equality and comparison operations. */
static void fuzz_field_equality(const uint8_t *data, size_t size) {
    if (size > 31) {
        secp256k1_fe fe;    
        secp256k1_fe_set_b32_mod(&fe, data);
        CHECK(secp256k1_fe_equal(&fe, &fe));
        CHECK(secp256k1_fe_equal_var(&fe, &fe));
        CHECK(secp256k1_fe_cmp_var(&fe, &fe) == 0);
    }
}

/* Test conversions between 32-byte value and field element */ 
static void fuzz_field_b32_and_fe(const uint8_t *data, size_t size) {
    if (size > 31) {
        secp256k1_fe fe, fe2;
        unsigned char b32[32];        
        if (secp256k1_fe_set_b32_limit(&fe, data)) {
            secp256k1_fe_set_b32_mod(&fe2, data);
            CHECK(secp256k1_fe_cmp_var(&fe, &fe2) == 0);
            secp256k1_fe_get_b32(b32, &fe);
            CHECK(secp256k1_memcmp_var(b32, data, 32) == 0);       
        } else {
            secp256k1_fe_set_b32_mod(&fe2, data);
            secp256k1_fe_get_b32(b32, &fe2);
            CHECK(secp256k1_memcmp_var(b32, data, 32) == 0);
        } 
    }
}

/* Test conversions between field element and secp256k1_fe_storage */ 
static void fuzz_field_fe_and_storage(const uint8_t *data, size_t size) {
    if (size > 31) {
        secp256k1_fe fe, fe2;
        secp256k1_fe_storage fes;     
        secp256k1_fe_set_b32_mod(&fe, data);
        secp256k1_fe_to_storage(&fes, &fe);
        secp256k1_fe_from_storage(&fe2, &fes);
        CHECK(secp256k1_fe_equal_var(&fe, &fe2));
    }
}

/* Test commutativity of addition on two field elements */ 
static void fuzz_field_add_commutativty(const uint8_t *data, size_t size) {
    if (size > 63) {        
        secp256k1_fe a, b, r1, r2;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_set_b32_mod(&b, data + 32);
        r1 = a;
        secp256k1_fe_add(&r1, &b);
        r2 = b;
        secp256k1_fe_add(&r2, &a);
        CHECK(secp256k1_fe_equal_var(&r1, &r2));
    }
}

/* Test associativity of addition on field elements */
static void fuzz_field_add_associativity(const uint8_t *data, size_t size) {
    if (size > 95) {     
        secp256k1_fe a, b, c, r1, r2;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_set_b32_mod(&b, data + 32);
        secp256k1_fe_set_b32_mod(&c, data + 64);       
        r1 = a;
        secp256k1_fe_add(&r1, &b);
        secp256k1_fe_add(&r1, &c);
        r2 = c;
        secp256k1_fe_add(&r2, &b);
        secp256k1_fe_add(&r2, &a);
        CHECK(secp256k1_fe_equal_var(&r1, &r2));
    }
}

/* Test identity addition on field elements */ 
static void fuzz_field_add_zero(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_fe a, zero, r1;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_clear(&zero);
        r1 = a;
        secp256k1_fe_add(&r1, &zero);
        CHECK(secp256k1_fe_equal_var(&r1, &a));
    }
}

/* Test addition of field element and its negative value */ 
static void fuzz_field_add_negate(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_fe a, negate;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_negate(&negate, &a, 1);
        secp256k1_fe_add(&a, &negate);
        CHECK(secp256k1_fe_normalizes_to_zero_var(&a));
    }
}

/* Test addition of field element and an integer */ 
static void fuzz_field_add_integer(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_fe a, r1, r2;
        int v = size;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_set_int(&r1, v);
        secp256k1_fe_add(&r1, &a);
        r2 = a;
        secp256k1_fe_add_int(&r2, v);
        CHECK(secp256k1_fe_equal_var(&r1, &r2));
    }
}

/* Test the half value of a field element */ 
static void fuzz_field_half(const uint8_t *data, size_t size) {
    if (size > 31) {
        secp256k1_fe fe, fe2;
        secp256k1_fe_set_b32_mod(&fe, data);
        fe2 = fe;
        secp256k1_fe_half(&fe);
        secp256k1_fe_add(&fe, &fe);
        CHECK(secp256k1_fe_equal_var(&fe, &fe2));
        secp256k1_fe_add(&fe2, &fe2);
        secp256k1_fe_half(&fe2);
        CHECK(secp256k1_fe_equal_var(&fe, &fe2));
    }
}

/* Test commutativity of multiplication on two field elements */
static void fuzz_field_mul_commutativity(const uint8_t *data, size_t size) {
    if (size > 63) {        
        secp256k1_fe a, b, r1, r2;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_set_b32_mod(&b, data + 32);
        secp256k1_fe_mul(&r1, &a, &b);
        secp256k1_fe_mul(&r2, &b, &a);
        CHECK(secp256k1_fe_equal_var(&r1, &r2));
    }
}

/* Test associativity of multiplication on field elements */
static void fuzz_field_mul_associativity(const uint8_t *data, size_t size) {
    if (size > 95) {     
        secp256k1_fe a, b, c, r1, r2;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_set_b32_mod(&b, data + 32);
        secp256k1_fe_set_b32_mod(&c, data + 64);       
        secp256k1_fe_mul(&r1, &a, &b);
        secp256k1_fe_mul(&r1, &r1, &c);
        secp256k1_fe_mul(&r2, &b, &c);
        secp256k1_fe_mul(&r2, &r2, &a);
        CHECK(secp256k1_fe_equal_var(&r1, &r2));
    }
}

/* Test distributivity of multiplication on field elements */
static void fuzz_field_mul_distributivity(const uint8_t *data, size_t size) {
    if (size > 95) {     
        secp256k1_fe a, b, c, r1, r2, r3;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_set_b32_mod(&b, data + 32);
        secp256k1_fe_set_b32_mod(&c, data + 64);
        r1 = a;       
        secp256k1_fe_add(&r1, &b);
        secp256k1_fe_mul(&r1, &r1, &c);
        secp256k1_fe_mul(&r2, &a, &c);
        secp256k1_fe_mul(&r3, &b, &c);
        secp256k1_fe_add(&r2, &r3);
        CHECK(secp256k1_fe_equal_var(&r1, &r2));
    }
}

/* Test field multiplication with 0 */ 
static void fuzz_field_mul_zero(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_fe a, zero, r1;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_clear(&zero);
        secp256k1_fe_mul(&r1, &a, &zero);
        CHECK(secp256k1_fe_is_zero(&r1));
    }
}

/* Test multiplication of field element with an integer */
static void fuzz_field_mul_integer(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_fe a, r1, r2;
        secp256k1_fe_set_b32_mod(&a, data);
        r1 = a;
        secp256k1_fe_mul_int(&r1, 3);
        r2 = a;
        secp256k1_fe_add(&r2, &a);
        secp256k1_fe_add(&r2, &a);
        CHECK(secp256k1_fe_equal_var(&r1, &r2));
    }
}

/* Test square of a field element */
static void fuzz_field_sqr(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_fe a, r1, r2;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_sqr(&r1, &a);
        secp256k1_fe_mul(&r2, &a, &a);
        CHECK(secp256k1_fe_equal_var(&r1, &r2));
    }
}

/* Test square of negative field element */
static void fuzz_field_sqr_negate(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_fe a, b, r1, r2;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_negate(&b, &a, 1);
        secp256k1_fe_sqr(&r1, &a);
        secp256k1_fe_sqr(&r2, &b);
        CHECK(secp256k1_fe_equal_var(&r1, &r2));
    }
}

/* Test square root of a field element */
static void fuzz_field_sqrt(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_fe a, b, r1, r2;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_sqr(&b, &a);
        secp256k1_fe_sqrt(&r1, &b);
        secp256k1_fe_negate(&r2, &r1, 1);
        secp256k1_fe_add(&r1, &a); 
        secp256k1_fe_add(&r2, &a);
        secp256k1_fe_normalize(&r1); 
        secp256k1_fe_normalize(&r2);
        CHECK(secp256k1_fe_is_zero(&r1) || secp256k1_fe_is_zero(&r2));
    }
}

/* Test square root of negative field element */
static void fuzz_field_sqrt_negate(const uint8_t *data, size_t size) {
    if (size > 31) {        
        secp256k1_fe a, b, r1, r2;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_normalize(&a);
        if (!secp256k1_fe_is_zero(&a)) {
            secp256k1_fe_negate(&b, &a, 1);
            int ret = secp256k1_fe_sqrt(&r1, &a);
            int ret2 = secp256k1_fe_sqrt(&r2, &b);
            CHECK((ret2 == 0) || (ret == 0));
        } else {
            secp256k1_fe_sqrt(&r1, &a);
            CHECK(secp256k1_fe_is_zero(&r1));
        }
    }
}

/* Test field inverse */
static void fuzz_field_inverse(const uint8_t *data, size_t size) {
    if (size > 31) {     
        secp256k1_fe a, r1, r2, r3;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_inv(&r1, &a);
        if (secp256k1_fe_normalizes_to_zero(&a)) {
            CHECK(secp256k1_fe_normalizes_to_zero(&r1));
        }
        else {
            secp256k1_fe_mul(&r2, &a, &r1);
            secp256k1_fe_add_int(&r2, -1);
            CHECK(secp256k1_fe_normalizes_to_zero(&r2));
        }
    }
} 

/* Test conditional move of field elements */
static void fuzz_field_cmov(const uint8_t *data, size_t size) {
    if (size > 63) {        
        secp256k1_fe a, b, r1;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_set_b32_mod(&b, data + 32);
        int flag = size % 2;
        r1 = a;
        if (flag) {            
            secp256k1_fe_cmov(&r1, &b, 1);
            CHECK(secp256k1_fe_equal_var(&r1, &b));
        } else {
            secp256k1_fe_cmov(&r1, &b, 0);
            CHECK(secp256k1_fe_equal_var(&r1, &a));
        }
    }
}

/* Test conditional move of fe_storage */
static void fuzz_field_storage_cmov(const uint8_t *data, size_t size) {
    if (size > 63) {        
        secp256k1_fe a, b;
        secp256k1_fe_storage as, bs, rs1;
        secp256k1_fe_set_b32_mod(&a, data);
        secp256k1_fe_set_b32_mod(&b, data + 32);
        secp256k1_fe_to_storage(&as, &a);
        secp256k1_fe_to_storage(&bs, &b);
        int flag = size % 2;
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

typedef void (*fuzz_function)(const uint8_t* data, size_t size);

static fuzz_function selected_fuzz_function = NULL;

int LLVMFuzzerInitialize(int *argc, char ***argv) {
    const char* test_name = getenv("FUZZ");
    if (!test_name) {
        fprintf(stderr, "Select a fuzz test using the FUZZ environment variable\n");
        assert(false);
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
    } else if (strcmp(test_name, "field_equality") == 0) {
        selected_fuzz_function = &fuzz_field_equality;
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
    } else if (strcmp(test_name, "field_sqr_negate") == 0) {
        selected_fuzz_function = &fuzz_field_sqr_negate;
    } else if (strcmp(test_name, "field_sqrt") == 0) {
        selected_fuzz_function = &fuzz_field_sqrt;
    } else if (strcmp(test_name, "field_sqrt_negate") == 0) {
        selected_fuzz_function = &fuzz_field_sqrt_negate;
    } else if (strcmp(test_name, "field_inverse") == 0) {
        selected_fuzz_function = &fuzz_field_inverse;
    } else if (strcmp(test_name, "field_cmov") == 0) {
        selected_fuzz_function = &fuzz_field_cmov;
    } else if (strcmp(test_name, "field_storage_cmov") == 0) {
        selected_fuzz_function = &fuzz_field_storage_cmov;
    } else {
        fprintf(stderr, "Unknown fuzz test selected using FUZZ environment variable: %s\n", test_name);
        assert(false);
    }
    return 0;
}

int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    selected_fuzz_function(data, size);
    return 0;
}



        
        