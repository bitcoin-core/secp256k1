/**********************************************************************
 * Copyright (c) 2017 Andrew Poelstra                                 *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_SCRATCH_IMPL_H_
#define _SECP256K1_SCRATCH_IMPL_H_

#include "util.h"
#include "scratch.h"

static secp256k1_scratch* secp256k1_scratch_create(const secp256k1_callback* error_callback, size_t size) {
    const size_t base_alloc = ((sizeof(secp256k1_scratch) + ALIGNMENT - 1) / ALIGNMENT) * ALIGNMENT;
    void *alloc = checked_malloc(error_callback, base_alloc + size);
    secp256k1_scratch* ret = (secp256k1_scratch *)alloc;
    if (ret != NULL) {
        memset(ret, 0, sizeof(*ret));
        memcpy(ret->magic, "scratch", 8);
        ret->data = (void *) ((char *) alloc + base_alloc);
        ret->max_size = size;
    }
    return ret;
}

static void secp256k1_scratch_destroy(const secp256k1_callback* error_callback, secp256k1_scratch* scratch) {
    if (scratch != NULL) {
        VERIFY_CHECK(scratch->frame == 0);
        if (memcmp(scratch->magic, "scratch", 8) != 0) {
            secp256k1_callback_call(error_callback, "invalid scratch space");
            return;
        }
        memset(scratch->magic, 0, sizeof(scratch->magic));
        free(scratch);
    }
}

static size_t secp256k1_scratch_max_allocation(const secp256k1_callback* error_callback, const secp256k1_scratch* scratch, size_t objects) {
    size_t i = 0;
    size_t allocated = 0;
    if (memcmp(scratch->magic, "scratch", 8) != 0) {
        secp256k1_callback_call(error_callback, "invalid scratch space");
        return 0;
    }
    for (i = 0; i < scratch->frame; i++) {
        allocated += scratch->frame_size[i];
    }
    if (scratch->max_size - allocated <= objects * (ALIGNMENT - 1)) {
        return 0;
    }
    return scratch->max_size - allocated - objects *  (ALIGNMENT - 1);
}

static int secp256k1_scratch_allocate_frame(const secp256k1_callback* error_callback, secp256k1_scratch* scratch, size_t n, size_t objects) {
    VERIFY_CHECK(scratch->frame < SECP256K1_SCRATCH_MAX_FRAMES);

    if (memcmp(scratch->magic, "scratch", 8) != 0) {
        secp256k1_callback_call(error_callback, "invalid scratch space");
        return 0;
    }

    if (n <= secp256k1_scratch_max_allocation(error_callback, scratch, objects)) {
        n += objects * (ALIGNMENT - 1);
        scratch->current_frame = scratch->data;
        scratch->data = (void *) ((char *) scratch->data + n);
        scratch->frame_size[scratch->frame] = n;
        scratch->offset[scratch->frame] = 0;
        scratch->frame++;
        return 1;
    } else {
        return 0;
    }
}

static void secp256k1_scratch_deallocate_frame(const secp256k1_callback* error_callback, secp256k1_scratch* scratch) {
    if (memcmp(scratch->magic, "scratch", 8) != 0) {
        secp256k1_callback_call(error_callback, "invalid scratch space");
        return;
    }

    VERIFY_CHECK(scratch->frame > 0);

    scratch->frame--;
    scratch->data = (void *) ((char *) scratch->data - scratch->frame_size[scratch->frame]);
}

static void *secp256k1_scratch_alloc(const secp256k1_callback* error_callback, secp256k1_scratch* scratch, size_t size) {
    void *ret;
    size_t frame = scratch->frame - 1;
    size = ROUND_TO_ALIGN(size);

    if (memcmp(scratch->magic, "scratch", 8) != 0) {
        secp256k1_callback_call(error_callback, "invalid scratch space");
        return NULL;
    }

    if (scratch->frame == 0 || size + scratch->offset[frame] > scratch->frame_size[frame]) {
        return NULL;
    }
    ret = (void *) ((char *) scratch->current_frame + scratch->offset[frame]);
    memset(ret, 0, size);
    scratch->offset[frame] += size;

    return ret;
}

#endif
