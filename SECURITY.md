# Security Policy

## Reporting a Vulnerability

To report security issues send an email to secp256k1-security@bitcoincore.org (not for support).

See the [threat model](#threat-model) below for the security goals of the library and for which issues should be reported privately and which should be reported publicly.

The following keys may be used to communicate sensitive information to developers:

| Name                 | Fingerprint                                        |
|----------------------|----------------------------------------------------|
| Pieter Wuille        | 133E AC17 9436 F14A 5CF1  B794 860F EB80 4E66 9320 |
| Tim Ruffing          | 09E0 3F87 1092 E40E 106E  902B 33BC 86AB 80FF 5516 |
| Sebastian Falbesoner | 6A8F 9C26 6528 E25A EB1D  7731 C237 1D91 CB71 6EA7 |

You can import a key by running the following command with that individual’s fingerprint: `gpg --keyserver hkps://keys.openpgp.org --recv-keys "<fingerprint>"` Ensure that you put quotes around fingerprints containing spaces.

## Threat Model

This section describes the security goals of libsecp256k1 as an implementation, and the resulting vulnerability reporting policy. It does not cover the security of the implemented cryptographic schemes and protocols themselves, which is analyzed in their specifications (mostly [Bitcoin Improvement Proposals](https://github.com/bitcoin/bips)) and in associated research papers. Vulnerabilities at the scheme or protocol level, i.e., those that stem from issues in specifications or papers rather than from the implementation, are nevertheless covered by the reporting policy (see 3.3).

### 1. Scope and definitions

#### 1.1 Covered code and versions

In scope is the library itself (`src/` and `include/`, excluding the items below) in the latest release and on the `master` branch, including all modules and configuration options. This explicitly includes experimental modules and configuration options, i.e., those that require `--enable-experimental` (Autotools) or `-DSECP256K1_EXPERIMENTAL=ON` (CMake).

Out of scope are tests, benchmarks, examples, precomputation tools, the build system, everything in `contrib/`, `sage/` and `tools/` (including the test vector generation scripts), and builds with `-DVERIFY`. `contrib/` contains code that is not part of the library, even where applications copy it. Issues in out-of-scope code, including examples that demonstrate insecure API usage, are welcome as regular public issues.

#### 1.2 Definitions

A *vulnerability* is any issue that an attacker can exploit to cause harm, or that leads to disclosure of secret data, crashes or incorrect results in honest use. The security goals in section 2 make this concrete for specific kinds of issues. Issues that fall under the non-goals in 2.5, or that require violating documented API preconditions (see 2.2), are not vulnerabilities.

*Secret data* means:

- Secret keys, including inside keypair objects.
- Secret nonces and the randomness used to derive them, such as the auxiliary randomness for signing and the MuSig2 session randomness.
- Shared secrets, such as ECDH results.
- Other inputs and outputs that the API documents as secret.
- Anything else that a user can reasonably expect to be secret.
- Intermediate values derived from any of the above that are not intended to be public.

Public keys, signatures, messages, public nonces and other values that a protocol publishes are not secret, and neither is information the library intentionally reveals, such as whether a secret key or a derived nonce is valid. Functions that only process public data, such as signature verification, are intentionally variable-time.

### 2. Security goals

#### 2.1 Cryptographic correctness

The library must correctly implement the algorithms and protocols it provides, in accordance with their specifications and the API documentation. This includes key derivation and validation, nonce derivation and protocol state handling (including measures against nonce reuse), use of caller-provided randomness as specified, validation of externally supplied inputs (including those received from other participants in a multi-party protocol), and handling of exceptional conditions and failure cases, including the documented return and output values on failure. API documentation that would lead a caller who follows it to use the library insecurely also violates this goal.

#### 2.2 Robustness and availability

Valid and adversarial inputs within the documented API contract must not cause crashes, memory corruption, undefined behavior or disproportionate resource consumption. Any argument that takes external input, such as serialized public keys, signatures, messages and tweaks, may be chosen by an attacker. This includes data received from other participants in a multi-party protocol, such as public nonces and partial signatures from a MuSig2 co-signer.

Violations of documented API preconditions are out of scope, such as passing invalid pointers or uninitialized objects, modifying opaque objects other than through the API, and violating the thread-safety rules for context objects. The library only performs lightweight sanity checks on its objects, such as checking magic bytes. Expensive consistency checks, such as checking that an internal group element lies on the curve, are not intended. Externally supplied inputs must nevertheless be validated as required by the API.

Aborting through the illegal argument callback on a detected API violation is intended. Aborting through the error callback is intended if the cause lies outside the library, such as memory exhaustion, hardware failure, miscompilation or memory corruption by the application. If valid or adversarial inputs can trigger the error callback while the API is used as documented, this is a vulnerability.

#### 2.3 No secret-dependent control flow or memory access

In production builds (see 3.2), code that operates on secret data (see 1.2) must not have secret-dependent control flow or memory access (including table lookups), and must not use instructions or library functions with secret-dependent timing (subject to the exclusions in 2.5). This applies to the compiled code: a violation introduced by compiler optimizations or platform-specific behavior counts, even if the source code is constant-time. This protects against timing and related software side channels, for example an attacker who measures the execution time of library operations, remotely or locally, or who observes memory access patterns through shared caches.

#### 2.4 Clearing of secret data

The library must clear secret data from memory it manages once it is no longer needed. This covers stack variables and buffers, unintended copies, and caller-owned objects that the API documents as cleared, such as a MuSig2 secret nonce after signing and outputs on failure (not clearing these also violates 2.1). Clearing operations must be implemented in a way that prevents their removal by compiler optimizations. This limits what an attacker learns who obtains memory contents of the process after a library call has returned, for example through an unrelated memory disclosure bug in the application.

The result is best-effort: the library cannot clear copies that the compiler keeps in registers or stack slots. Clearing other caller-owned memory, such as the buffer a secret key was passed in, is the caller's responsibility.

#### 2.5 Non-goals

The following are outside the security goals:

- Physical attacks, such as power analysis, electromagnetic analysis and fault injection. The library includes hardening that can make some of these attacks harder, such as context randomization (blinding) and auxiliary randomness in nonce derivation, but makes no claim about how effective it is.
- Speculative execution attacks and other microarchitectural leaks that are not caused by secret-dependent control flow or memory access in the library's code.
- Hardware on which basic arithmetic instructions have data-dependent timing, such as ARM32 cores with an early-terminating multiplier.
- An attacker who can read or modify process memory while the library operates on secret data, and mechanisms that copy process memory elsewhere, such as swapping, core dumps and hibernation.
- Weak or reused randomness supplied by the caller. The library does not provide a random number generator.
- Misbehavior of code supplied by the caller, such as custom nonce functions, hash functions, callbacks and compile-time overrides of library defaults.

### 3. Vulnerability reporting policy

#### 3.1 Primary configurations

For the reporting matrix in 3.3, a primary configuration is one of the following platform and compiler combinations, built with any released version of the listed compiler:

| Operating system | Architecture | Compiler              |
|------------------|--------------|-----------------------|
| Linux            | x86_64       | GCC, Clang            |
| Linux            | i686         | GCC, Clang            |
| Linux            | ARM32        | GCC                   |
| Linux            | ARM64        | GCC, Clang            |
| Linux            | PPC64LE      | GCC                   |
| macOS            | x86_64       | GCC, Clang            |
| macOS            | ARM64        | GCC, Clang            |
| Windows          | x86_64       | MSVC, clang-cl, MinGW |
| Windows          | x86          | MSVC, MinGW           |

Unreleased compiler versions such as development snapshots, bare-metal targets and all platforms not listed are other configurations. The list may change as platform and compiler support evolves. Automated constant-time tests cover only some of these configurations and parts of the API, and are not a proof of constant-time behavior. Violations of 2.3 in production builds are nevertheless S (see 3.3) in all primary configurations.

#### 3.2 Build modes

A *production build* uses `-O1` (or `-O`) to `-O3` (the build system default is `-O2`), or `/O2` with MSVC, without sanitizers, coverage or other instrumentation. Builds with `-O0`, `-Og`, `-Os`, `-Oz`, `-Ofast`, `/Od` or `/O1` are not production builds. Size-optimized builds (`-Os`, `-Oz`, `/O1`) are excluded because they make it more likely that the compiler turns branch-free code into secret-dependent branches. CI runs the automated constant-time tests mainly at `-O2`; `-O1` and `-O3` are covered only on Linux x86_64 (`-O3` only with Clang).

#### 3.3 Reporting matrix

- **S (security issue):** report privately as described in [Reporting a Vulnerability](#reporting-a-vulnerability).
- **P (public issue):** report as a regular public issue or open a pull request. These are handled as regular bugs, not confidentially.

A *primary production build* is a production build (see 3.2) of a primary configuration (see 3.1). *Other builds* are all other builds that are in scope (see 1.1). If an issue violates more than one security goal, it is S if it is S under any of them.

| Violated security goal                   | Primary production builds | Other builds |
|------------------------------------------|:-------------------------:|:------------:|
| Cryptographic correctness<sup>1)</sup>   |             S             |      S       |
| Robustness and availability<sup>1)</sup> |             S             |      S       |
| Constant-time execution (see 2.3)        |             S             |      P       |
| Clearing of secret data<sup>2)</sup>     |             P             |      P       |

<sup>1)</sup> If such an issue turns out to be caused by a compiler bug, it may be resolved in the compiler rather than in the library.

<sup>2)</sup> P because exploiting leftover secret data requires a separate memory disclosure, and the protection is best-effort (see 2.4).

The matrix applies to vulnerabilities as defined in 1.2. A vulnerability that fits none of the rows is S. Issues that are not vulnerabilities, such as undefined behavior without any observable effect or documentation errors that do not lead to insecure use, are always P. If in doubt, report privately.

A vulnerability in an implemented scheme, protocol or specification itself, rather than in its implementation, is S. Since such an issue likely affects other implementations as well, it may be coordinated with the authors of the specification.

Issues that are not vulnerabilities because they fall under the non-goals in 2.5 or require violating documented API preconditions (see 1.2) can be raised publicly, for example as hardening suggestions, but there is no commitment to address them.
