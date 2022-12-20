# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.2.0] - 2022-12-12

#### Added
 - Added usage examples for common use cases in a new `examples/` directory.
 - Added `secp256k1_selftest`, to be used in conjunction with `secp256k1_context_static`.
 - Added support for 128-bit wide multiplication on MSVC for x86_64 and arm64, giving roughly a 20% speedup on those platforms.

#### Changed
 - Enabled modules `schnorrsig`, `extrakeys` and `ecdh` by default in `./configure`.
 - The `secp256k1_nonce_function_rfc6979` nonce function, used by default by `secp256k1_ecdsa_sign`, now reduces the message hash modulo the group order to match the specification. This only affects improper use of ECDSA signing API.

#### Deprecated
 - Deprecated context flags `SECP256K1_CONTEXT_VERIFY` and `SECP256K1_CONTEXT_SIGN`. Use `SECP256K1_CONTEXT_NONE` instead.
 - Renamed `secp256k1_context_no_precomp` to `secp256k1_context_static`.
 - Module `schnorrsig`: renamed `secp256k1_schnorrsig_sign` to `secp256k1_schnorrsig_sign32`.

#### ABI Compatibility

Since this is the first release, we do not compare application binary interfaces.
However, there are earlier unreleased versions of libsecp256k1 that are *not* ABI compatible with this version.

## [0.1.0] - 2013-03-05 to 2021-12-25

This version was in fact never released.
The number was given by the build system since the introduction of autotools in Jan 2014 (ea0fe5a5bf0c04f9cc955b2966b614f5f378c6f6).
Therefore, this version number does not uniquely identify a set of source files.

[unreleased]: https://github.com/bitcoin-core/secp256k1/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/bitcoin-core/secp256k1/compare/423b6d19d373f1224fd671a982584d7e7900bc93..v0.2.0
[0.1.0]: https://github.com/bitcoin-core/secp256k1/commit/423b6d19d373f1224fd671a982584d7e7900bc93
