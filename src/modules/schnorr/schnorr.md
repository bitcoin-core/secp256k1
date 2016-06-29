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
* 32-byte big endian unsigned integer `R.x` in the range `[0..p-1]`
* 32-byte big endian unsigned integer `s` in the range `[0..order-1]`

Stage 1 partial multisignatures:
* 32-byte big endian unsigned integer `R.x` in the range `[0..p-1]`

For a valid signature for message `m` with public key `Q` the following
It is computed as:

##### Signing

Inputs:
* 32-byte message `m`
* 32-byte scalar private key `x` (`!=0`)
* 32-byte scalar private nonce `k` (`!=0`)

Steps:
* Compute public nonce `R = k * G`.
* If R.y is not a quadratic residue, negate `k` and `R`.
* Compute scalar `e = SHA256(R.x || m)`. If `e == 0` or `e >= order`, fail.
* Compute scalar `s = k - e * x`.
* The signature is `(R.x, s)`.

##### Verification (method 1)

Inputs:
* 32-byte message `m`
* public key point `Q`
* signature pair (field element `R.x`, scalar `s`)

Steps:
* Signature is invalid if `s >= order`.
* Signature is invalid if `R.x >= p`.
* Compute scalar `e = SHA256(R.x || m)`. Signature is invalid if `e == 0` or
  `e >= order`
* Compute point `R' = e * Q + s * G`. Signature is invalid if `R'` is infinity
  or `R'.y` is not a quadratic residue.
* Signature is valid if `R'.x == R.x`.

This method is faster for single signature verification.

##### Verification (method 2)

Inputs:
* 32-byte message `m`
* public key point `Q`
* signature pair (field element `R.x`, scalar `s`)

Steps:
* Signature is invalid if `s >= order`.
* Signature is invalid if `R.x >= p`.
* Compute scalar `e = SHA256(R.x || m)`. Signature is invalid if `e == 0` or
  `e >= order`.
* Decompress `R.x` into point `R'`, such that its `y` coordinate is a quadratic
  residue. Fail if `R'` is not on the curve.
* Signature is valid if `R == e * Q + s * G.

As this results in a verification equation that is entirely in the point domain,
it can be adapted easily for batch verification or public key recovery.

##### Multisigning combined public key

Inputs:
* Public keys `Q(j) = x(j) * G` from all cosigners, for all `j`

Steps:
* Multiply each of the `Q(j)` values by their hash `SHA256(Q(j))`.
* Compute the sum `Q_all` of all `Q(j)` values.
* The full combined public key is `Q_all`.

##### Multisigning stage 1

Inputs:
* 32-byte message `m`
* 32-byte scalar private nonce `k(i)` (`!=0`)

Steps:
* Compute public nonce `R(i) = k(i) * G`.
* The partial signature is `R(i).x`.

##### Multisigning stage 2

Inputs:
* 32-byte message `m`
* 32-byte scalar private key `x(i)` (`!=0`)
* 32-byte scalar private nonce `k(i)` (`!=0`)
* Partial stage 1 signatures `R(j).x` from all other cosigners, for all `j != i`

Steps:
* Tweak the private key: multiply `x(i)` by `SHA256(x(i) * G)`.
* Compute (or reuse from stage 1) public nonce `R(i) = k(i) * G`.
* If `R(i).y` is not a quadratic residue, negate `k(i)` and `R(i)`.
* Convert each `R(j).x` coordinate into an `R(j)` point such that its `y`
  coordinate is a quadratic residue.
* Compute the sum `R_all(i)` of all the `R(j)` points, including your own
  `R(i)`.
* If `R_all.y` is not a quadratic residue, negate `k(i)` and `R_all(i)`.
* Compute scalar `e = SHA256(R_all(i).x || m)`. If `e == 0` or `e >= order`,
  fail.
* Compute scalar `s(i) = k(i) - e * x`.
* The partial stage 2 signature is `(R_all(i).x, s(i))`.

##### Multisigning combine stage 2 signatures into a full signature

Inputs:
* Partial stage 2 signatures `(R_all(j).x, s(j))` from all cosigners, for all
  `j`

Steps:
* Check whether all `R_all(j).x` values in each of the stage 2 signature are
  identical. If not, fail.
* Compute the sum `s_all` of all `s(j)` values.
* The full combined signature is `(R_all.x, s(i))`.

### Design choices

##### Verifying `R`'s `y` coordinate

In order to support batch verification and public key recovery, the full `R`
point must be known to verifiers, rather than just its `x` coordinate. In order
to not risk being more strict in batch verification than normal verification,
verifiers must be required to reject signatures with incorrect `y` coordinate.

This is only possible by:
* Including the `y` coordinate in the signature, making it very cheap to verify,
  but increases the signature size by 32 bytes.
* Including enough information in the signature to recover the `y` coordinate
  from the `x` coordinate. As every valid `x` only has two corresponding `y`
  coordinates, only one bit is needed.
* Outlawing one of the two possible `y` coordinates. As the signer can trivially
  switch from one `y` to the other by negating R, this has negligable
  performance overhead compared to the previous option, and saves one bit.

The mechanism chosen here is to require that the `y` coordinate is a quadratic
residue (its Legendre symbol modulo the field size has to be one). This is cheap
to compute, and can be done directly with Jacobian coordinates. Alternative
symmetry breakers (like requiring `y` to be even, or in the lower half of the
range) require a (slow) conversion to affine coordinates first.

##### Multiplying public keys by their hash in multisigning

In multisignatures we don't sign with key `x`, but with `x * SHA256(x * G)`.
This is done to prevent an attack where participants claim their public key is a
point that has been constructed to cancel out other participants' keys.

For example, if there are 3 participants `P1`, `P2` and `P3`, with private keys
`x1`, `x2`, and `x3`. After `P1` and `P2` have revealed their public keys as
`Q1 = x1 * G` and `Q2 = x2 * G` respectively, `P3` can claim his public key is
`Q3 = x3 * G - Q1 - Q2`. `P3` cannot sign with this key, but the resulting
combined public key would be `Q1 + Q2 + Q3`, which is in this case equal to
`Q1 + Q2 + x3 * G - Q1 - Q2` or just `x3 * G`, which `P3` can sign for without
cooperation from `P1` or `P2`.

It is of course possible to demand that whenever someone computes a combined
public key, they verify that all constituent public keys carry a valid signature
from their own private key. But this is a non-obvious requirement, and not
enforcable within the signature scheme itself.

Instead we choose to sign with tweaked private keys, and get a signature that is
valid for the combined public key
`Q_all = Q1 * SHA256(Q1) + Q2 * SHA256(Q2) + Q3 * SHA256(Q3)` instead of for
`Q_all = Q1 + Q2 + Q3`. It is impossible for any of the participants to make
other participants' keys cancel out in this case.

Proof:
* Assume `Q = Q1 * H(Q1) + Q2 * H(Q2) + ...`.
* Assume we have a point `R` and scalar `y` such that
  `Q_all = Q + H(R) * R = y * G`.
* Let `H'(x) = 1 / H(x) mod n`, so `Q + R / H'(R) = y * G`.
* Multiply both sides by `H'(R)`, so `Q * H'(R) + R = H'(R) * y * G`
* Move everything to the left side, so `Q * H'(R) + R - H'(R) * y * G = 0`.
* Let scalar `s = -H'(R) * y`, so `R + Q * H'(R) + s * G = 0`.
* Assume `H(x) = SHA256(x || m)`, for some value of `m`.
* We now have `R + Q * (1 / SHA256(R || m)) + s * G = 0`, or `(R, s)` is a valid
  Schnorr signature for hash function `H'(x) = 1 / SHA256(x) mod n` on message
  `m` with public key `Q`. If `H'(x)` is a random oracle (which it is when
  `SHA256 mod n` is), this is presumed to be only possible to someone who knows
  `x` such that `Q = x * G`.
* Thus, you can only pick a public key `R` that enables you to sign for the
  combined multiparty public key `Q_all = Q + R * H(R)` if you already know the
  private key `x` for the others' combined multiparty public key `Q`.
