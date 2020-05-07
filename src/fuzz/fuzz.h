#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "include/secp256k1.h"

typedef struct {
    const unsigned char* data;
    size_t remaining;
} fuzzed_data_provider;

static fuzzed_data_provider initialize_fuzzed_data_provider(const unsigned char* data, size_t size) {
    fuzzed_data_provider res;
    res.data = data;
    res.remaining = size;

    return res;
}

/* Should check remaining bounds *before* calling this */
static void advance(fuzzed_data_provider* provider, size_t num) {
    provider->data += num;
    provider->remaining -= num;
}

/* Consumes num bytes from the provider, returns NULL if there's not enough data left. */
static const unsigned char* consume_bytes(fuzzed_data_provider* provider, size_t num) {
    if (num > provider->remaining) {
        return NULL;
    } else {
        const unsigned char* res = provider->data;
        advance(provider, num);
        return res;
    }
}

/* Consumes at least 32 bytes until it find a valid seckey, returns NULL if there's not enough data left */
static const unsigned char* consume_seckey(fuzzed_data_provider* provider) {
    const unsigned char* end = provider->data + provider->remaining;
    const unsigned char* seckey;
    if (provider->remaining < 32) {
        return NULL;
    }

    while (!secp256k1_ec_seckey_verify(secp256k1_context_no_precomp, provider->data)) {
        if (++provider->data > end - 32) {
            provider->remaining = end - provider->data;
            return NULL;
        }
    }
    seckey = provider->data;
    provider->data += 32;
    provider->remaining = end - provider->data;
    return seckey;
}

/* Consumes at least 33 bytes until it find a valid pubkey, returns 1 on sucess and returns 0 if there's not enough data left
* (have 50% probablity of finding a key for uniforma random bytes)
*/
static int consume_pubkey(fuzzed_data_provider* provider, secp256k1_pubkey* res) {
    const unsigned char* end = provider->data + provider->remaining;
    unsigned char pubkey[33];
    if (provider->remaining < 33) {
        return 0;
    }

    pubkey[0] = 0x02 + (provider->data[0] & 1);
    memcpy(pubkey, provider->data + 1, 32);

    while(!secp256k1_ec_pubkey_parse(secp256k1_context_no_precomp, res, pubkey, 33)) {
        if (++provider->data > end - 33) {
            provider->remaining = end - provider->data;
            return 0;
        }
        pubkey[0] = 0x02 + (provider->data[0] & 1);
        memcpy(pubkey, provider->data + 1, 32);
    }
    provider->data += 33;
    provider->remaining = end - provider->data;
    return 1;
}

/* Consume an int from the provider and returns it, defaults to zero if the provider is empty. */
static int consume_int(fuzzed_data_provider* provider) {
    int res = 0;
    int bytes_to_copy;

    if (provider->remaining > sizeof(int)) {
        bytes_to_copy = sizeof(int);
    } else {
        bytes_to_copy = provider->remaining;
    }

    memcpy(&res, provider->data, bytes_to_copy);
    advance(provider, bytes_to_copy);
    return res;
}

void initialize(void);
void test_one_input(fuzzed_data_provider* provider);
