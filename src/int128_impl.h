/***********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_INT128_IMPL_H
#define SECP256K1_INT128_IMPL_H

#include "util.h"

#include "int128.h"

#if defined(SECP256K1_WIDEMUL_INT128)
#  if defined(SECP256K1_INT128_NATIVE)
#    include "int128_native_impl.h"
#  elif defined(SECP256K1_INT128_STRUCT)
#    include "int128_struct_impl.h"
#  else
#    error "Please select int128 implementation"
#  endif
#endif

#endif
