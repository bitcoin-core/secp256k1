/**********************************************************************
 * Copyright (c) 2017 Tomas van der Wansem                            *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/


#ifndef _SECP256K1_HOMOMORPHIC_
# define _SECP256K1_HOMOMORPHIC_

# include "secp256k1.h"


# ifdef __cplusplus
extern "C" {
# endif


/** Opaque intermediate roller; this is actually a group element **/
typedef struct {
    unsigned char d[64];
} secp256k1_roller;



/** Adds one roller to another
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:    pointer to a context object (cannot be NULL)
 *  In/Out:  roller: the roller to which the input roller must be added
 *  In:      input:  the roller to add
 */
SECP256K1_API int secp256k1_multiset_add_roller(
  const secp256k1_context* ctx,
  secp256k1_roller *roller,
  const secp256k1_roller *input

) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Removes one roller from another
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:    pointer to a context object (cannot be NULL)
 *  In/Out:  roller: the roller from which the input roller must be removed
 *  In:      input:  the roller to remove
 */
SECP256K1_API int secp256k1_multiset_remove_roller(
  const secp256k1_context* ctx,
  secp256k1_roller *roller,
  const secp256k1_roller *input

) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);


/** Creates a roller from arbitrary data
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:      pointer to a context object (cannot be NULL)
 *  Out:     roller:   the resulting roller
 *  In:      input:    the data to add
 *           inputLen: the size of the data to add
 */
SECP256K1_API int secp256k1_multiset_create_roller(
  const secp256k1_context* ctx,
  secp256k1_roller *roller,
  const unsigned char *input,
  size_t inputLen
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);

/** Converts a roller to a hash
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:      pointer to a context object (cannot be NULL)
 *  Out:     hash:     the resulting 32-byte hash
 *  In:      roller:   the roller to hash
 */
SECP256K1_API int secp256k1_multiset_finalize_roller(
  const secp256k1_context* ctx,
  unsigned char *resultHash,
  const secp256k1_roller *roller
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2) SECP256K1_ARG_NONNULL(3);


/** Initialize an empty roller
 *  The resulting roller is the roller for 0-length data
 *
 *  Returns: 1: success
 *           0: invalid parameter
 *  Args:    ctx:      pointer to a context object (cannot be NULL)
 *  Out:     roller:   the resulting roller
 */
SECP256K1_API int secp256k1_multiset_init_roller(
  const secp256k1_context* ctx,
  secp256k1_roller *roller
) SECP256K1_ARG_NONNULL(1) SECP256K1_ARG_NONNULL(2);


# ifdef __cplusplus
}
# endif

#endif
