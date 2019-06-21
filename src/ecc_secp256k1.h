typedef struct {
  uint8_t _0[64];
} EcdsaSig;

typedef struct {
  uint8_t _0[64];
} SchnorrSig;

/**
 * Sign an ECDSA Signature
 * The message should be a hashed 32 bytes.
 * Returns:
 * 1 - Finished successfully.
 * 0 - Failed.
 */
int ecc_secp256k1_ecdsa_sign(EcdsaSig *sig_out,
                             const unsigned char *msg,
                             const unsigned char *privkey);

/**
 * Sign a Schnorr Signature
 * The message should be a hashed 32 bytes.
 * Returns:
 * 1 - Finished successfully.
 * 0 - Failed.
 */
int ecc_secp256k1_schnorr_sign(SchnorrSig *sig_out,
                               const unsigned char *msg,
                               const unsigned char *privkey);

/**
 * Verify a ECDSA Signature
 * Accepts either compressed(33) or uncompressed(6) public key. using the flag (1==compressed, 0==uncompressed).
 * The message should be a hashed 32 bytes.  (***Make Sure you hash the message yourself! otherwise it's easily broken***)
 * Returns:
 * 1 - The signature is valid.
 * 0 - Signature is not valid.
 * -1 - Some other problem.
 */
int secp256k1_ec_ecdsa_verify(const EcdsaSig *sig,
                              const unsigned char *msg,
                              const unsigned char *pubkey,
                              int compressed);

/**
 * Verify a Schnorr Signature
 * Accepts either compressed(33) or uncompressed(64) public key. using the flag (1==compressed, 0==uncompressed).
 * The message should be a hashed 32 bytes.  (***Make Sure you hash the message yourself! otherwise it's easily broken***)
 * Returns:
 * 1 - The signature is valid.
 * 0 - Signature is not valid.
 * -1 - Some other problem.
 */
int secp256k1_ec_schnorr_verify(const SchnorrSig *sig,
                                const unsigned char *msg,
                                const unsigned char *pubkey,
                                int compressed);
