# Build Options

This document describes available options when building with:
- GNU Autotools (hereafter "Autotools")
- CMake
- C toolchain only, for instance, GNU C compiler and GNU Binutils (hereafter "Manual")

Autotools options must be provided to the `./configure` script.

CMake options must be provided to the `cmake` when generating a buildsystem.

In manual builds, options are just compiler flags.

## Library Type

By default, when using Autotools, both the shared and static libsecp256k1 libraries are built.
However, when using CMake, only one type of the library is built (see [PR1230](https://github.com/bitcoin-core/secp256k1/pull/1230)).

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-shared=yes` | `yes`, `no` |
| Autotools | `--enable-static=yes` | `yes`, `no` |
| CMake | `-DBUILD_SHARED_LIBS=ON` | `ON`, `OFF` |
| CMake | `-DSECP256K1_DISABLE_SHARED=OFF` | `ON`, `OFF` |

## Optional Modules

### ECDH Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-ecdh=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_ECDH=ON` | `ON`, `OFF` |
| Manual | n/a | `-DENABLE_MODULE_ECDH=1` |

### ECDSA Pubkey Recovery Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-recovery=no` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_RECOVERY=OFF` | `ON`, `OFF` |
| Manual | n/a | `-DENABLE_MODULE_RECOVERY=1` |

### Extrakeys Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-extrakeys=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_EXTRAKEYS=ON` | `ON`, `OFF` |
| Manual | n/a | `-DENABLE_MODULE_EXTRAKEYS=1` |

### Schnorrsig Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-extrakeys=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_SCHNORRSIG=ON` | `ON`, `OFF` |
| Manual | n/a | `-DENABLE_MODULE_SCHNORRSIG=1` |

### ElligatorSwift Module

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-module-ellswift=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_ENABLE_MODULE_ELLSWIFT=ON` | `ON`, `OFF` |
| Manual | n/a | `-DENABLE_MODULE_ELLSWIFT=1` |

## Precomputed Table Parameters

### Window Size

Window size for ecmult precomputation for verification, specified as integer in range [2..24].
Larger values result in possibly better performance at the cost of an exponentially larger precomputed table.
The table will store 2^(SIZE-1) * 64 bytes of data but can be larger in memory due to platform-specific padding and alignment.
A window size larger than 15 will require you delete the prebuilt `precomputed_ecmult.c` file so that it can be rebuilt.
For very large window sizes, use `make -j 1` to reduce memory use during compilation.
`auto`/`AUTO` is a reasonable setting for desktop machines (currently 15).

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--with-ecmult-window=auto` | `auto`, [`2`..`24`] |
| CMake | `-DSECP256K1_ECMULT_WINDOW_SIZE=AUTO` | `AUTO`, [`2`..`24`] |
| Manual | `-DECMULT_WINDOW_SIZE=15` | [`2`..`24`] |

### Precision Bits

Precision bits to tune the precomputed table size for signing.
The size of the table is 32kB for 2 bits, 64kB for 4 bits, 512kB for 8 bits of precision.
A larger table size usually results in possible faster signing.
`auto`/`AUTO` is a reasonable setting for desktop machines (currently 4).

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--with-ecmult-gen-precision=auto` | `auto`, `2`, `4`, `8` |
| CMake | `-DSECP256K1_ECMULT_GEN_PREC_BITS=AUTO` | `AUTO`, `2`, `4`, `8` |
| Manual | `-DECMULT_GEN_PREC_BITS=4` | `2`, `4`, `8` |

## Optional Features

### Assembly Optimization

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--with-asm=auto` | `auto`, `no`, `x86_64`, `arm32` |
| CMake | `-DSECP256K1_ASM=AUTO` | `AUTO`, `OFF`, `x86_64`, `arm32` |
| Manual | n/a | `-DUSE_ASM_X86_64=1`, `-DUSE_EXTERNAL_ASM=1` |

`arm32` assembly optimization is an [experimental](#experimental-options) option.

### External Default Callback Functions

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-external-default-callbacks=no` | `yes`, `no` |
| CMake | `-DSECP256K1_USE_EXTERNAL_DEFAULT_CALLBACKS=OFF` | `ON`, `OFF` |
| Manual | n/a | `-DUSE_EXTERNAL_DEFAULT_CALLBACKS=1` |

For more details, see docs in [`secp256k1.h`](/include/secp256k1.h).

### Wide Multiplication Implementation

This is a _test-only_ override of the "widemul" setting.
Legal values are:
- `int64` (for `[u]int64_t`)
- `int128` (for `[unsigned] __int128`)
- `int128_struct` (for `int128` implemented as a structure)
- `auto`/`AUTO` (for autodetection by the C code)

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--with-test-override-wide-multiply=auto` | `auto`, `int64`, `int128`, `int128_struct` |
| CMake | `-DSECP256K1_TEST_OVERRIDE_WIDE_MULTIPLY=AUTO` | `AUTO`, `int64`, `int128`, `int128_struct` |
| Manual | n/a | `-DUSE_FORCE_WIDEMUL_INT64=1`, `-DUSE_FORCE_WIDEMUL_INT128=1`, `-DUSE_FORCE_WIDEMUL_INT128_STRUCT=1` |

## Experimental Options

To use experimental options, they must be allowed explicitly.

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-experimental=no` | `yes`, `no` |
| CMake | `-DSECP256K1_EXPERIMENTAL=OFF` | `ON`, `OFF` |

## Optional Binaries

### Benchmarks

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-benchmark=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_BUILD_BENCHMARK=ON` | `ON`, `OFF` |

For more details, see docs in [README](/README.md#benchmark).

### Tests

#### Tests with and without `VERIFY` mode

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-tests=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_BUILD_TESTS=ON` | `ON`, `OFF` |

#### Exhaustive Tests

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-exhaustive-tests=yes` | `yes`, `no` |
| CMake | `-DSECP256K1_BUILD_EXHAUSTIVE_TESTS=ON` | `ON`, `OFF` |

#### Constant-time Tests

To build this tool, a memory-checking interface is required: [Valgrind](#build-with-valgrind) or MSan.

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-ctime-tests=yes` if Valgrind enabled | `yes`, `no` |
| CMake | `-DSECP256K1_BUILD_CTIME_TESTS=ON` if Valgrind enabled | `ON`, `OFF` |

##### Build with Valgrind

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--with-valgrind=auto` | `auto`, `yes`, `no` |
| CMake | `-DSECP256K1_VALGRIND=AUTO` | `AUTO`, `ON`, `OFF` |

#### Coverage Analysis Support

|   | Option with the default value | Available option values |
|---|-------------------------------|-------------------------|
| Autotools | `--enable-coverage=no` | `yes`, `no` |
| CMake | `-DSECP256K1_COVERAGE=OFF` | `ON`, `OFF` |

For more details, see docs in [README](/README.md#test-coverage).
