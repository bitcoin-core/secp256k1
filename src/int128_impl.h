#ifndef SECP256K1_INT128_IMPL_H
#define SECP256K1_INT128_IMPL_H

#include "int128.h"
#include "util.h"

#if defined HAVE_CONFIG_H
#include "libsecp256k1-config.h"
#endif

#if defined(SECP256K1_INT128_NATIVE)
#include "int128_native_impl.h"
#elif defined(SECP256K1_INT128_STRUCT)
#include "int128_struct_impl.h"
#else
#error "Please select int128 implementation"
#endif

#endif
