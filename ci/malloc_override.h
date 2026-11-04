/* Used to test building the library with custom memory allocation
 * functions. Each block starts with a header that stores its size, so that
 * freeing with a wrong size fails. */

#include <assert.h>
#include <stdlib.h>
#include <string.h>

/* Keeps the returned memory as aligned as the memory returned by malloc. */
#define SECP256K1_CI_HEADER_SIZE 16

__attribute__((unused)) static void *secp256k1_ci_malloc(size_t size) {
    unsigned char *p;
    assert(size != 0);
    p = malloc(SECP256K1_CI_HEADER_SIZE + size);
    if (p == NULL) {
        return NULL;
    }
    memcpy(p, &size, sizeof(size));
    return p + SECP256K1_CI_HEADER_SIZE;
}

__attribute__((unused)) static void secp256k1_ci_free(void *ptr, size_t size) {
    unsigned char *p;
    size_t alloc_size;
    assert(ptr != NULL);
    assert(size != 0);
    p = (unsigned char *)ptr - SECP256K1_CI_HEADER_SIZE;
    memcpy(&alloc_size, p, sizeof(alloc_size));
    assert(alloc_size == size);
    free(p);
}

#define malloc secp256k1_ci_do_not_call_malloc_directly
#define free secp256k1_ci_do_not_call_free_directly
