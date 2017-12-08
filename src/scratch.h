/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra	                              *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_SCRATCH_
#define _SECP256K1_SCRATCH_

/* The typedef is used internally; the struct name is used in the public API
 * (where it is exposed as a different typedef) */
typedef struct secp256k1_scratch_space_struct {
    void *data;
    size_t offset;
    size_t init_size;
    size_t max_size;
    const secp256k1_callback* error_callback;
} secp256k1_scratch;

static secp256k1_scratch* secp256k1_scratch_create(const secp256k1_callback* error_callback, size_t init_size, size_t max_size);
static void secp256k1_scratch_destroy(secp256k1_scratch* scratch);

/** Returns the maximum allocation the scratch space will allow */
static size_t secp256k1_scratch_max_allocation(const secp256k1_scratch* scratch, size_t n_objects);

/** Attempts to allocate so that there are `n` available bytes. Returns 1 on success, 0 on failure */
static int secp256k1_scratch_resize(secp256k1_scratch* scratch, size_t n, size_t n_objects);

/** Returns a pointer into the scratch space or NULL if there is insufficient available space */
static void *secp256k1_scratch_alloc(secp256k1_scratch* scratch, size_t n);

/** Resets the returned pointer to the beginning of space */
static void secp256k1_scratch_reset(secp256k1_scratch* scratch);

#endif
