libsecp256k1
============

[![Build Status](https://api.cirrus-ci.com/github/bitcoin-core/secp256k1.svg?branch=master)](https://cirrus-ci.com/github/bitcoin-core/secp256k1)
![Dependencies: None](https://img.shields.io/badge/dependencies-none-success)
[![irc.libera.chat #secp256k1](https://img.shields.io/badge/irc.libera.chat-%23secp256k1-success)](https://web.libera.chat/#secp256k1)

Optimized C library for ECDSA signatures and secret/public key operations on curve secp256k1.

This library is intended to be the highest quality publicly available library for cryptography on the secp256k1 curve. However, the primary focus of its development has been for usage in the Bitcoin system and usage unlike Bitcoin's may be less well tested, verified, or suffer from a less well thought out interface. Correct usage requires some care and consideration that the library is fit for your application's purpose.

Features:
* secp256k1 ECDSA signing/verification and key generation.
* Additive and multiplicative tweaking of secret/public keys.
* Serialization/parsing of secret keys, public keys, signatures.
* Constant time, constant memory access signing and public key generation.
* Derandomized ECDSA (via RFC6979 or with a caller provided function.)
* Very efficient implementation.
* Suitable for embedded systems.
* No runtime dependencies.
* Optional module for public key recovery.
* Optional module for ECDH key exchange.
* Optional module for Schnorr signatures according to [BIP-340](https://github.com/bitcoin/bips/blob/master/bip-0340.mediawiki).

Implementation details
----------------------

* General
  * No runtime heap allocation.
  * Extensive testing infrastructure.
  * Structured to facilitate review and analysis.
  * Intended to be portable to any system with a C89 compiler and uint64_t support.
  * No use of floating types.
  * Expose only higher level interfaces to minimize the API surface and improve application security. ("Be difficult to use insecurely.")
* Field operations
  * Optimized implementation of arithmetic modulo the curve's field size (2^256 - 0x1000003D1).
    * Using 5 52-bit limbs (including hand-optimized assembly for x86_64, by Diederik Huys).
    * Using 10 26-bit limbs (including hand-optimized assembly for 32-bit ARM, by Wladimir J. van der Laan).
      * This is an experimental feature that has not received enough scrutiny to satisfy the standard of quality of this library but is made available for testing and review by the community.
* Scalar operations
  * Optimized implementation without data-dependent branches of arithmetic modulo the curve's order.
    * Using 4 64-bit limbs (relying on __int128 support in the compiler).
    * Using 8 32-bit limbs.
* Modular inverses (both field elements and scalars) based on [safegcd](https://gcd.cr.yp.to/index.html) with some modifications, and a variable-time variant (by Peter Dettman).
* Group operations
  * Point addition formula specifically simplified for the curve equation (y^2 = x^3 + 7).
  * Use addition between points in Jacobian and affine coordinates where possible.
  * Use a unified addition/doubling formula where necessary to avoid data-dependent branches.
  * Point/x comparison without a field inversion by comparison in the Jacobian coordinate space.
* Point multiplication for verification (a*P + b*G).
  * Use wNAF notation for point multiplicands.
  * Use a much larger window for multiples of G, using precomputed multiples.
  * Use Shamir's trick to do the multiplication with the public key and the generator simultaneously.
  * Use secp256k1's efficiently-computable endomorphism to split the P multiplicand into 2 half-sized ones.
* Point multiplication for signing
  * Use a precomputed table of multiples of powers of 16 multiplied with the generator, so general multiplication becomes a series of additions.
  * Intended to be completely free of timing sidechannels for secret-key operations (on reasonable hardware/toolchains)
    * Access the table with branch-free conditional moves so memory access is uniform.
    * No data-dependent branches
  * Optional runtime blinding which attempts to frustrate differential power analysis.
  * The precomputed tables add and eventually subtract points for which no known scalar (secret key) is known, preventing even an attacker with control over the secret key used to control the data internally.

Build steps
-----------

libsecp256k1 is built using autotools:

    $ ./autogen.sh
    $ ./configure
    $ make
    $ make check  # run the test suite
    $ sudo make install  # optional


To compile optional modules (such as Schnorr signatures), you need to run `./configure` with additional flags (such as `--enable-module-schnorrsig`). Run `./configure --help` to see the full list of available flags and environment variables.

Configuration flags
-----------

The build process recognizes the following flags. Unless otherwise specified, valid values for each option are "yes" and "no".

### Toggle Dev-Mode

| Autotools           | Manual             | Default |
|---------------------|--------------------|---------|
| `--enable-dev_mode` | None               | no      |

In dev mode, all binaries and modules are enabled by default but individual options can still be overridden explicitly. Options may have different default values when in dev-mode. This option is hidden from `./configure --help`.


### Enable Coverage

| Autotools           | Manual              | Default | Default (dev-mode) |
|---------------------|---------------------|---------|--------------------|
| `--enable-coverage` | `-DENABLE_COVERAGE` | no      | no                 |

Enable compiler flags to support kcov coverage analysis. Compiles out all VERIFY code as a side effect.

### Enable Benchmarks

| Autotools            | Manual               | Default | Default (dev-mode) |
|----------------------|----------------------|---------|--------------------|
| `--enable-benchmark` | `-DENABLE_BENCHMARK` | yes     | yes                |

Additionally compile the benchmarks.


### Enable Tests

| Autotools        | Manual           | Default | Default (dev-mode) |
|------------------|------------------|---------|--------------------|
| `--enable-tests` | `-DENABLE_TESTS` | yes     | yes                |

Additionally compile the tests.

### Enable Exhaustive tests

| Autotools                   | Manual                      | Default | Default (dev-mode) |
|-----------------------------|-----------------------------|---------|--------------------|
| `--enable-exhaustive-tests` | `-DENABLE_EXHAUSTIVE_TESTS` | yes     | yes                |

Additionally compile the tests.

### Enable Examples

| Autotools           | Manual              | Default | Default (dev-mode) |
|---------------------|---------------------|---------|--------------------|
| `--enable-examples` | `-DENABLE_EXAMPLES` | no      | yes                |

Additionally compile the examples.

### Enable Valgrind Checks

| Autotools         | Manual | Default   | Default (dev-mode)  |
|-------------------|--------|-----------|---------------------|
| `--with-valgrind` | None   | auto      | auto                |

Build with extra checks for running inside Valgrind. Valid values are "yes", "no", and "auto".

### Enable External Default Callbacks

| Autotools                             | Manual                               | Default | Default (dev-mode) |
|---------------------------------------|--------------------------------------|---------|--------------------|
| `--enable-external-default-callbacks` | `-DUSE_EXTERNAL_DEFAULT_CALLBACKS`   | no      | no                 |

Enable external default callback functions. Ensure that you supply them in your code, otherwise you will get a linker error.

### Allow Experimental Options

| Autotools               | Manual                  | Default | Default (dev-mode) |
|-------------------------|-------------------------|---------|--------------------|
| `--enable-experimental` | `-DENABLE_EXPERIMENTAL` | no      | yes                |

Allow passing of experimental build options. The following options are experimental:

- `--with-asm=arm`

### Enable ECDH Module

| Autotools              | Manual                 | Default | Default (dev-mode) |
|------------------------|------------------------|---------|--------------------|
| `--enable-module-ecdh` | `-DENABLE_MODULE_ECDH` | no      | yes                |

Enable the ECDH module.

### Enable Recovery Module

| Autotools                  | Manual                     | Default | Default (dev-mode) |
|----------------------------|----------------------------|---------|--------------------|
| `--enable-module-recovery` | `-DENABLE_MODULE_RECOVERY` | no      | yes                |

Enable the ECDSA public key recovery module.

### Enable Extrakeys Module

| Autotools                   | Manual                      | Default | Default (dev-mode) |
|-----------------------------|-----------------------------|---------|--------------------|
| `--enable-module-extrakeys` | `-DENABLE_MODULE_EXTRAKEYS` | no      | yes                |

Enable the extrakeys module. Extrakeys exports miscellaneous and supplimentary public key functions.

### Enable Schnorrsig Module

| Autotools                    | Manual                       | Default | Default (dev-mode) |
|------------------------------|------------------------------|---------|--------------------|
| `--enable-module-schnorrsig` | `-DENABLE_MODULE_SCHNORRSIG` | no      | yes                |

Enable the Schnorr signatures module.

### Override `widemul` Setting

| Autotools                            | Manual    | Default | Default (dev-mode) |
|--------------------------------------|-----------|---------|--------------------|
| `--with-test-override-wide-multiply` | See below | auto    | auto               |

Test-only override of the (autodetected by the C code) "widemul" setting, used in the multiplication implementation. Legal values are "int64" (for `[u]int64_t`), "int128" (for `[unsigned] __int128`), and "auto" (the default).

`-DUSE_FORCE_WIDEMUL_INT128` is passed when "int128" is specified, and `-DUSE_FORCE_WIDEMUL_INT64` is passed when int64 is specified. Neither option is passed when "auto" is specified.

### Assembly Optimizations

| Autotools    | Manual    | Default | Default (dev-mode) |
|--------------|-----------|---------|--------------------|
| `--with-asm` | See below | auto    | auto               |

Specifies the assembly options to use. Legal values are "x86_64", "arm", "no", and "auto". Please note that --with-asm=arm is an experimental option (see [Allow Experimental Options](#allow-experimental-options).

`-USE_ASM_X86_64` is passed when "x86_64" is specified. `-DUSE_EXTERNAL_ASM` is passed when "arm" is passed. When "auto" is passed, the system checks if assembly optimizations are available for the current architecture and sets one of the above macros accordingly. Passing "none" completely disables assembly optimizations.

### Tune `ecmult` Table Window

| Autotools              | Manual                 | Default | Default (dev-mode) |
|------------------------|------------------------|---------|--------------------|
| `--with-ecmult-window` | `-DECMULT_WINDOW_SIZE` | auto    | auto               |

Window size for ecmult precomputation for verification, specified as integer in range `[2..24]`. Larger values result in possibly better performance at the cost of an exponentially larger precomputed table. The table will store `2^(SIZE-1) * 64` bytes of data but can be larger in memory due to platform-specific padding and alignment. A window size larger than 15 will require you delete the prebuilt precomputed_ecmult.c file so that it can be rebuilt. For very large window sizes, use `make -j 1` to reduce memory use during compilation. "auto" is a reasonable setting for desktop machines (currently 15).

### Tune `ecmult` Bit Precision

| Autotools                     | Manual                   | Default | Default (dev-mode) |
|-------------------------------|--------------------------|---------|--------------------|
| `--with-ecmult-gen-precision` | `-DECMULT_GEN_PREC_BITS` | auto    | auto               |

Precision bits to tune the precomputed table size for signing. Valid values are "2", "4", "8", and "auto". The size of the table is 32kB for 2 bits, 64kB for 4 bits, 512kB for 8 bits of precision. A larger table size usually results in possible faster signing. "auto" is a reasonable setting for desktop machines (currently 4).

Usage examples
-----------
Usage examples can be found in the [examples](examples) directory. To compile them you need to configure with `--enable-examples`.
  * [ECDSA example](examples/ecdsa.c)
  * [Schnorr signatures example](examples/schnorr.c)
  * [Deriving a shared secret (ECDH) example](examples/ecdh.c)

To compile the Schnorr signature and ECDH examples, you also need to configure with `--enable-module-schnorrsig` and `--enable-module-ecdh`.

Test coverage
-----------

This library aims to have full coverage of the reachable lines and branches.

To create a test coverage report, configure with `--enable-coverage` (use of GCC is necessary):

    $ ./configure --enable-coverage

Run the tests:

    $ make check

To create a report, `gcovr` is recommended, as it includes branch coverage reporting:

    $ gcovr --exclude 'src/bench*' --print-summary

To create a HTML report with coloured and annotated source code:

    $ mkdir -p coverage
    $ gcovr --exclude 'src/bench*' --html --html-details -o coverage/coverage.html

Benchmark
------------
If configured with `--enable-benchmark` (which is the default), binaries for benchmarking the libsecp256k1 functions will be present in the root directory after the build.

To print the benchmark result to the command line:

    $ ./bench_name

To create a CSV file for the benchmark result :

    $ ./bench_name | sed '2d;s/ \{1,\}//g' > bench_name.csv

Reporting a vulnerability
------------

See [SECURITY.md](SECURITY.md)
