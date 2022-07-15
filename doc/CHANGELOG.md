# Changelog

This file is currently only a template for future use.

Each change falls into one of the following categories: Added, Changed, Deprecated, Removed, Fixed or Security.

## [Unreleased]

### Changed
 - Enable modules schnorrsig, extrakeys and ECDH by default in ./configure

### Deprecated
 - Deprecated context flags `SECP256K1_CONTEXT_VERIFY` and `SECP256K1_CONTEXT_SIGN`. Use `SECP256K1_CONTEXT_NONE` instead.
 - Renamed `secp256k1_context_no_precomp` to `secp256k1_context_static`.

### Added
 - Added `secp256k1_selftest`, to be used in conjunction with `secp256k1_context_static`.

## [MAJOR.MINOR.PATCH] - YYYY-MM-DD

### Added/Changed/Deprecated/Removed/Fixed/Security
- [Title with link to Pull Request](https://link-to-pr)
