#include <check.h>
#include <stdlib.h>
#include <string.h>

#include "contrib/lax_der_privatekey_parsing.h"

START_TEST(test_privkey_length_field_bounds)
{
    /* Invariant: parsing must reject inputs where length field exceeds 32 bytes
       to prevent buffer underflow in memcpy destination calculation */
    
    /* Test payloads: DER-encoded private key structures with varying length fields */
    struct {
        unsigned char data[64];
        size_t len;
        int should_fail;
    } payloads[] = {
        /* Exploit case: privkey[1] = 0x40 (64) causes underflow: 32 - 64 = -32 */
        {{0x30, 0x40, 0x01, 0x02, 0x03}, 64, 1},
        /* Boundary case: privkey[1] = 0x21 (33) just over limit */
        {{0x30, 0x21, 0x01, 0x02, 0x03}, 35, 1},
        /* Valid case: privkey[1] = 0x20 (32) exactly at limit */
        {{0x30, 0x20, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
          0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10, 0x11, 0x12,
          0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c,
          0x1d, 0x1e, 0x1f, 0x20}, 34, 0},
    };
    int num_payloads = sizeof(payloads) / sizeof(payloads[0]);

    for (int i = 0; i < num_payloads; i++) {
        unsigned char out32[32];
        unsigned char canary_before[32];
        unsigned char canary_after[32];
        
        memset(canary_before, 0xAA, 32);
        memset(out32, 0x00, 32);
        memset(canary_after, 0xBB, 32);
        
        int result = ec_privkey_import_der(NULL, out32, payloads[i].data, payloads[i].len);
        
        /* If length field > 32, function must return failure (0) */
        if (payloads[i].should_fail) {
            ck_assert_int_eq(result, 0);
        }
    }
}
END_TEST

Suite *security_suite(void)
{
    Suite *s;
    TCase *tc_core;

    s = suite_create("Security");
    tc_core = tcase_create("Core");

    tcase_add_test(tc_core, test_privkey_length_field_bounds);
    suite_add_tcase(s, tc_core);

    return s;
}

int main(void)
{
    int number_failed;
    Suite *s;
    SRunner *sr;

    s = security_suite();
    sr = srunner_create(s);

    srunner_run_all(sr, CK_NORMAL);
    number_failed = srunner_ntests_failed(sr);
    srunner_free(sr);

    return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}