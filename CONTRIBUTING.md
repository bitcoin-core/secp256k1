# Contributing to libsecp256k1

## Scope

libsecp256k1 is a library for elliptic curve cryptography on the curve secp256k1, not a general-purpose cryptography library.
The library primarily serves the needs of the Bitcoin Core project but provides additional functionality for the benefit of the wider Bitcoin ecosystem.

## Adding new functionality or modules

The libsecp256k1 project welcomes contributions in the form of new functionality or modules, provided they are within the project's scope.

It is the responsibility of the contributors to convince the maintainers that the proposed functionality is within the project's scope, high-quality and maintainable.
Contributors are recommended to provide the following in addition to the new code:

* **Specification:**
    A specification can help significantly in reviewing the new code as it provides documentation and context.
    It may justify various design decisions, give a motivation and outline security goals.
    If the specification contains pseudocode, a reference implementation or test vectors, these can be used to compare with the proposed libsecp256k1 code.
* **Security Arguments:**
    In addition to a defining the security goals, it should be argued that the new functionality meets these goals.
    Depending on the nature of the new functionality, a wide range of security arguments are acceptable, ranging from being "obviously secure" to rigorous proofs of security.
* **Relevance Arguments:**
    The relevance of the new functionality for the Bitcoin ecosystem should be argued by outlining clear use cases.

These are not the only factors taken into account when considering to add new functionality.
The proposed new libsecp256k1 code must be of high quality, including API documentation and tests, as well as featuring a misuse-resistant API design.

We recommend reaching out to other contributors (see [Communication Channels](#communication-channels)) and get feedback before implementing new functionality.

## Communication channels

Most communication about libsecp256k1 occurs on the GitHub repository: in issues, pull request or on the discussion board.

Additionally, there is an IRC channel dedicated to libsecp256k1, with biweekly meetings (see channel topic).
The channel is `#secp256k1` on Libera Chat.
The easiest way to participate on IRC is with the web client, [web.libera.chat](https://web.libera.chat/#secp256k1).
Chat history logs can be found at https://gnusha.org/secp256k1/.

## Contributor workflow & peer review

The Contributor Workflow & Peer Review in libsecp256k1 are similar to Bitcoin Core's workflow and review processes described in Core's [CONTRIBUTING.md](https://github.com/bitcoin/bitcoin/blob/master/CONTRIBUTING.md).
