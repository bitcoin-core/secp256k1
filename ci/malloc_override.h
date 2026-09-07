/* Used to test building the library with custom memory allocation
 * functions. */

#include <assert.h>
#include <stdlib.h>

__attribute__((unused)) static void *secp256k1_ci_malloc(size_t size) {
    assert(size != 0);
    return malloc(size);
}

__attribute__((unused)) static void secp256k1_ci_free(void *ptr, size_t size) {
    assert(ptr != NULL);
    assert(size != 0);
    free(ptr);
}

#define malloc secp256k1_ci_do_not_call_malloc_directly
#define free secp256k1_ci_do_not_call_free_directly
