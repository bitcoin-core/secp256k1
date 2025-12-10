#ifndef SECP256K1_SHA_H
#define SECP256K1_SHA_H

#include "secp256k1.h"

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * SHA-256 block compression function.
 *
 * Performs the SHA-256 transform step on a single 64-byte message block,
 * updating the 8-word `state` in place. This is the raw block-level primitive:
 * no padding, no message scheduling across blocks, and no length encoding.
 * Only the compression function is applied.
 *
 * If `rounds` is greater than 1, the same 64-byte block is re-compressed
 * repeatedly onto the updated state.
 *
 * The caller must supply a fully-formed, 64-byte, block-aligned message block.
 *
 * @param state   Current hash state (8 x 32-bit words), updated in place.
 * @param block   Pointer to a 64-byte message block.
 * @param rounds  Number of times to apply the compression to this block.
 */
SECP256K1_API void secp256k1_sha256_transform(
        uint32_t *state,
        const unsigned char *block,
        size_t rounds
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_SHA_H */
