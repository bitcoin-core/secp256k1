#include <stdint.h>
extern void fiat_secp256k1_dettman_mul(uint64_t *r, const uint64_t *a,
                                       const uint64_t *b);

extern void fiat_secp256k1_dettman_square(uint64_t *r, const uint64_t *a);
