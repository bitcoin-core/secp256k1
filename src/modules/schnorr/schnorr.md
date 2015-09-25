Schnorr-SHA256 module
=====================

This module implements a custom Schnorr-based signature scheme.

Features:
* Fixed size 64-byte signatures
* Public key recovery without additional information
* Batch validation (not yet implemented)
* Multiparty signing with 2 rounds of communication but no setup

### Signature format

Signatures and stage 2 partial multisignatures:
* 32-byte big endian unsigned integer in the range [0..p-1], R.x.
* 32-byte big endian unsigned integer in the range [0..order-1], s.

Stage 1 partial multisignatures:
* 32-byte big endian unsigned integer in the range [0..p-1], R(i).x.
* 64-byte normal signature.

### Algorithm description

##### Signing

Inputs:
* 32-byte message m
* 32-byte scalar private key x (!=0)
* 32-byte scalar private nonce k (!=0)

Steps:
* Compute public nonce R = k * G.
* If R.y is odd, negate k and R.
* Compute scalar h = SHA256(R.x || m). If h == 0 or h >= order, fail.
* Compute scalar s = k - h * x.
* The signature is (R.x, s).

##### Verification (method 1)

Inputs:
* 32-byte message m
* public key point Q
* signature pair (32-byte r, scalar s)

Steps:
* Signature is invalid if s >= order.
* Signature is invalid if r >= p.
* Compute scalar h = Hash(r || m). Signature is invalid if h == 0 or h >= order.
* Compute point R = h * Q + s * G. Signature is invalid if R is infinity or R's
  y coordinate is odd.
* Signature is valid if the serialization of R's x coordinate equals r.

This method is faster for single signature verification.

##### Verification (method 2)

Inputs:
* 32-byte message m
* public key point Q
* signature pair (32-byte r, scalar s)

Steps:
* Signature is invalid if s >= order.
* Signature is invalid if r >= p.
* Compute scalar h = Hash(r || m). Signature is invalid if h == 0 or h >= order.
* Decompress x coordinate r into point R, with odd y coordinate. Fail if R is
  not on the curve.
* Signature is valid if R + h * Q + s * G == 0.

This method is needed for batch verification and public key recovery.

##### Multisigning stage 1

Inputs:
* 32-byte message m
* 32-byte scalar private key x(i) (!=0)
* 32-byte scalar private nonce k(i) (!=0)

Steps:
* Compute public nonce R(i) = k(i) * G.
* If R.y is odd, negate k(i) and R(i).
* Sign the message SHA256(R(i).x || m) with private key x(i), resulting in
  sig(i).
* The partial signature is (R(i).x, sig(i)).

##### Multisigning stage 2

Inputs:
* 32-byte message m
* 32-byte scalar private key x(i) (!=0)
* 32-byte scalar private nonce k(i) (!=0)
* Partial stage 1 signatures (R(j).x, sig(j)) from all other cosigners, for all
  j != i
* Public keys from all other cosigners, Q(j), for all j != i

Steps:
* Compute (or reuse from stage 1) public nonce R(i) = k(i) * G.
* If R(i).y is odd, negate k(i) and R(i).
* Verify for all j whether sig(j) is a valid signature for message
  SHA256(R(j).x || m). If not, fail.
* Convert each R(j).x coordinate into an R(j) point.
* Compute the sum Rall of all the R(j) points, including your own R(i).
* If Rall.y is odd, negate k(i) and Rall.
* Compute scalar h = SHA256(Rall.x || m). If h == 0 or h >= order, fail.
* Compute scalar s(i) = k(i) - h * x.
* The partial stage 2 signature is (Rall.x, s(i)).

##### Multisigning stage 3

Inputs:
* Partial stage 2 signatures (Rall.x, s(j)) from all other cosigners, for all j

Steps:
* Check whether all Rall.x values in each of the stage 2 signature are
  identical. If not, fail.
* Compute the sum sall of all s(i) values.
* The full combined signature is (Rall.x, s(i)).

### Design choices

##### Rationale for verifying R's Y coordinate:

In order to support batch verification and public key recovery, the full R point
must be known to verifiers, rather than just its x coordinate. In order to not
risk being more strict in batch verification than normal verification,
verifiers must be required to reject signatures with incorrect y coordinate.
This is only possible by including either:
* a field inverse to compute the affine coordinates of R
* a field square root to decompres the x coordinate into a full point R

Both are relatively slow operations, However, batch validation offers
potentially much higher benefits than this cost.

##### Rationale for having an implicit Y coordinate oddness

If we commit to having the full R point known to verifiers, there are two
mechanisms. Either include its oddness in the signature, or give it an implicit
fixed value. As the R y coordinate can be flipped by a simple negation of the
nonce, we choose the latter, as it comes with nearly zero impact on signing or
verification performance, and saves a byte in the signature.
