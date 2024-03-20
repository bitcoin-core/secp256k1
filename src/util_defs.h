#ifndef SECP256K1_UTIL_DEFS_H
#define SECP256K1_UTIL_DEFS_H

/* Global variable visibility */
/* See: https://github.com/bitcoin-core/secp256k1/issues/1181 */
#if !defined(_WIN32) && defined(__GNUC__) && (__GNUC__ >= 4)
# define SECP256K1_LOCAL_VAR extern __attribute__ ((visibility ("hidden")))
#else
# define SECP256K1_LOCAL_VAR extern
#endif

#endif /* SECP256K1_UTIL_DEFS_H */
