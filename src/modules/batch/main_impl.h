#ifndef SECP256K1_MODULE_BATCH_MAIN_H
#define SECP256K1_MODULE_BATCH_MAIN_H

#include "../../../include/secp256k1_batch.h"

/** Opaque data structure that holds information required for the batch verification.
 *
 *  Members:
 *       data: scratch space object that contains points (_gej) and their
 *             respective scalars. To be used in Multi-Scalar Multiplication
 *             algorithms such as Strauss and Pippenger.
 *    scalars: pointer to scalars allocated on the scratch space.
 *     points: pointer to points allocated on the scratch space.
 *       sc_g: scalar corresponding to the generator point (G) in Multi-Scalar
 *             Multiplication equation.
 *     sha256: contains hash of all the inputs (schnorrsig/tweaks) present in
 *             the batch object, expect the first input. Used for generating a random secp256k1_scalar
 *             for each term added by secp256k1_batch_add_*.
 *     sha256: contains hash of all inputs (except the first one) present in the batch.
 *             `secp256k1_batch_add_` APIs use these for randomizing the scalar (i.e., multiplying
 *             it with a newly generated scalar) before adding it to the batch.
 *        len: number of scalar-point pairs present in the batch.
 *   capacity: max number of scalar-point pairs that the batch can hold.
 *     result: tells whether the given set of inputs (schnorrsigs or tweak checks) is valid
 *             or invalid. 1 = valid and 0 = invalid. By default, this is set to 1
 *             during batch object creation (i.e., `secp256k1_batch_create`).
 *
 *  The following struct name is typedef as secp256k1_batch (in include/secp256k1_batch.h).
 */
struct secp256k1_batch_struct{
    secp256k1_scratch *data;
    secp256k1_scalar *scalars;
    secp256k1_gej *points;
    secp256k1_scalar sc_g;
    secp256k1_sha256 sha256;
    size_t len;
    size_t capacity;
    int result;
};

static size_t secp256k1_batch_scratch_size(int max_terms) {
    size_t ret = secp256k1_strauss_scratch_size(max_terms) + STRAUSS_SCRATCH_OBJECTS*16;
    VERIFY_CHECK(ret != 0);

    return ret;
}

/** Allocates space for `batch->capacity` number of scalars and points on batch
 *  object's scratch space */
static int secp256k1_batch_scratch_alloc(const secp256k1_callback* error_callback, secp256k1_batch* batch) {
    size_t checkpoint = secp256k1_scratch_checkpoint(error_callback, batch->data);
    size_t count = batch->capacity;

    VERIFY_CHECK(count > 0);

    batch->scalars = (secp256k1_scalar*)secp256k1_scratch_alloc(error_callback, batch->data, count*sizeof(secp256k1_scalar));
    batch->points = (secp256k1_gej*)secp256k1_scratch_alloc(error_callback, batch->data, count*sizeof(secp256k1_gej));

    /* If scalar or point allocation fails, restore scratch space to previous state */
    if (batch->scalars == NULL || batch->points == NULL) {
        secp256k1_scratch_apply_checkpoint(error_callback, batch->data, checkpoint);
        return 0;
    }

    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/batch")||SHA256("BIP0340/batch"). */
static void secp256k1_batch_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x79e3e0d2ul;
    sha->s[1] = 0x12284f32ul;
    sha->s[2] = 0xd7d89e1cul;
    sha->s[3] = 0x6491ea9aul;
    sha->s[4] = 0xad823b2ful;
    sha->s[5] = 0xfacfe0b6ul;
    sha->s[6] = 0x342b78baul;
    sha->s[7] = 0x12ece87cul;

    sha->bytes = 64;
}

secp256k1_batch* secp256k1_batch_create(const secp256k1_context* ctx, size_t max_terms, const unsigned char *aux_rand16) {
    size_t batch_size;
    secp256k1_batch* batch;
    size_t batch_scratch_size;
    unsigned char zeros[16] = {0};

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(max_terms != 0);

    batch_size = sizeof(secp256k1_batch);
    batch = (secp256k1_batch *)checked_malloc(&ctx->error_callback, batch_size);
    batch_scratch_size = secp256k1_batch_scratch_size(max_terms);
    if (batch != NULL) {
        /* create scratch space inside batch object, if that fails return NULL*/
        batch->data = secp256k1_scratch_create(&ctx->error_callback, batch_scratch_size);
        if (batch->data == NULL) {
            return NULL;
        }
        /* allocate memeory for `max_terms` number of scalars and points on scratch space */
        batch->capacity = max_terms;
        if (!secp256k1_batch_scratch_alloc(&ctx->error_callback, batch)) {
            /* if scratch memory allocation fails, free all the previous the allocated memory
            and return NULL */
            secp256k1_scratch_destroy(&ctx->error_callback, batch->data);
            free(batch);
            return NULL;
        }

        /* set remaining data members */
        secp256k1_scalar_clear(&batch->sc_g);
        secp256k1_batch_sha256_tagged(&batch->sha256);
        if (aux_rand16 != NULL) {
            secp256k1_sha256_write(&batch->sha256, aux_rand16, 16);
        } else {
            /* use 16 bytes of 0x0000...000, if no fresh randomness provided */
            secp256k1_sha256_write(&batch->sha256, zeros, 16);
        }
        batch->len = 0;
        batch->result = 1;
    }

    return batch;
}

void secp256k1_batch_destroy(const secp256k1_context *ctx, secp256k1_batch *batch) {
    VERIFY_CHECK(ctx != NULL);

    if (batch != NULL) {
        if(batch->data != NULL) {
            /* can't destroy a scratch space with non-zero size */
            secp256k1_scratch_apply_checkpoint(&ctx->error_callback, batch->data, 0);
            secp256k1_scratch_destroy(&ctx->error_callback, batch->data);
        }
        free(batch);
    }
}

#endif /* SECP256K1_MODULE_BATCH_MAIN_H */
