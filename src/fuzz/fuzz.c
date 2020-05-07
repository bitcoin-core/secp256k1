#include <stdint.h>
#include <stddef.h>
#include "fuzz.h"

/* Default initialization: Override using a non-weak initialize(). */
__attribute__((weak)) void initialize(void) {}


/* This function is used by libFuzzer */
int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    fuzzed_data_provider provider = initialize_fuzzed_data_provider(data, size);
    test_one_input(&provider);
    return 0;
}

/* This function is used by libFuzzer */
int LLVMFuzzerInitialize(int* argc, char*** argv)
{
    (void)argc;
    (void)argv;
    initialize();
    return 0;
}
