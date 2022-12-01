#ifndef SECP256K1_H
#define SECP256K1_H

#ifdef __cplusplus
extern "C" {
#endif

/** TODO Add some text that explains how the header files are organized */

/** Opaque data structure that holds context information
 *
 *  The primary purpose of context objects is to store randomization data for
 *  enhanced protection against side-channel leakage. This protection is only
 *  effective if the context is randomized after its creation. See
 *  secp256k1_context_create for creation of contexts and
 *  secp256k1_context_randomize for randomization.
 *
 *  A secondary purpose of context objects is to store pointers to callback
 *  functions that the library will call when certain error states arise. See
 *  secp256k1_context_set_error_callback as well as
 *  secp256k1_context_set_illegal_callback for details. Future library versions
 *  may use context objects for additional purposes.
 *
 *  A constructed context can safely be used from multiple threads
 *  simultaneously, but API calls that take a non-const pointer to a context
 *  need exclusive access to it. In particular this is the case for
 *  secp256k1_context_destroy, secp256k1_context_preallocated_destroy,
 *  and secp256k1_context_randomize.
 *
 *  Regarding randomization, either do it once at creation time (in which case
 *  you do not need any locking for the other calls), or use a read-write lock.
 */
typedef struct secp256k1_context_struct secp256k1_context;

/** Opaque data structure that holds rewritable "scratch space"
 *
 *  The purpose of this structure is to replace dynamic memory allocations,
 *  because we target architectures where this may not be available. It is
 *  essentially a resizable (within specified parameters) block of bytes,
 *  which is initially created either by memory allocation or TODO as a pointer
 *  into some fixed rewritable space.
 *
 *  Unlike the context object, this cannot safely be shared between threads
 *  without additional synchronization logic.
 */
typedef struct secp256k1_scratch_space_struct secp256k1_scratch_space;

#include "secp256k1_main.h"

/** Create a secp256k1 context object (in dynamically allocated memory).
 *
 *  This function uses malloc to allocate memory. It is guaranteed that malloc is
 *  called at most once for every call of this function. If you need to avoid dynamic
 *  memory allocation entirely, see secp256k1_context_static and the functions in
 *  secp256k1_preallocated.h.
 *
 *  Returns: a newly created context object.
 *  In:      flags: Always set to SECP256K1_CONTEXT_DEFAULT (see below).
 *
 *  Currently, the only valid non-deprecated flag is SECP256K1_CONTEXT_DEFAULT, which
 *  will create a context sufficient for all functionality currently offered by the
 *  library. All other (deprecated) flags will be treated as equivalent to the
 *  SECP256K1_CONTEXT_DEFAULT flag. Though the flags parameter primarily exists
 *  for historical reasons, future versions of the library may introduce new flags.
 *
 *  If the context is intended to be used for API functions that perform computations
 *  involving secret keys, e.g., signing and public key generation, then it is highly
 *  recommended to call secp256k1_context_randomize on the context before calling
 *  those API functions. This will provide enhanced protection against side-channel
 *  leakage, see secp256k1_context_randomize for details.
 *
 *  Do not create a new context object for each operation, as construction and
 *  randomization can take non-negligible time.
 */
SECP256K1_API secp256k1_context* secp256k1_context_create(
    unsigned int flags
) SECP256K1_WARN_UNUSED_RESULT;

/** Copy a secp256k1 context object (into dynamically allocated memory).
 *
 *  This function uses malloc to allocate memory. It is guaranteed that malloc is
 *  called at most once for every call of this function. If you need to avoid dynamic
 *  memory allocation entirely, see the functions in secp256k1_preallocated.h.
 *
 *  Returns: a newly created context object.
 *  Args:    ctx: an existing context to copy
 */
SECP256K1_API secp256k1_context* secp256k1_context_clone(
    const secp256k1_context* ctx
) SECP256K1_ARG_NONNULL(1) SECP256K1_WARN_UNUSED_RESULT;

/** Destroy a secp256k1 context object (created in dynamically allocated memory).
 *
 *  The context pointer may not be used afterwards.
 *
 *  The context to destroy must have been created using secp256k1_context_create
 *  or secp256k1_context_clone. If the context has instead been created using
 *  secp256k1_context_preallocated_create or secp256k1_context_preallocated_clone, the
 *  behaviour is undefined. In that case, secp256k1_context_preallocated_destroy must
 *  be used instead.
 *
 *  Args:   ctx: an existing context to destroy, constructed using
 *               secp256k1_context_create or secp256k1_context_clone
 */
SECP256K1_API void secp256k1_context_destroy(
    secp256k1_context* ctx
) SECP256K1_ARG_NONNULL(1);

#ifdef __cplusplus
}
#endif

#endif /* SECP256K1_H */
