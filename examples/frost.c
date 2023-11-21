/***********************************************************************
 * Copyright (c) 2023 Bank of Italy                                    *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <stdio.h>
#include <assert.h>
#include <string.h>
#include <stdint.h>

#include <secp256k1.h>
#include <secp256k1_frost.h>

#include "examples_util.h"

#define EXAMPLE_MAX_PARTICIPANTS 3
#define EXAMPLE_MIN_PARTICIPANTS 2

int main(void) {
    unsigned char msg[12] = "Hello World!";
    unsigned char msg_hash[32];
    unsigned char tag[14] = "frost_protocol";
    uint32_t index;
    unsigned char binding_seed[32] = {0};
    unsigned char hiding_seed[32] = {0};
    unsigned char signature[64];
    int is_signature_valid;
    int return_val;

    /* secp256k1 context used to sign and verify signatures */
    secp256k1_context *sign_verify_ctx;

    /* This example uses a centralized trusted dealer to generate keys. Alternatively,
     * FROST provides functions to run distributed key generation. See modules/frost/tests_impl.h */
    secp256k1_frost_vss_commitments *dealer_commitments;
    secp256k1_frost_keygen_secret_share shares_by_participant[3];
    /* keypairs stores private and public keys for each participant */
    secp256k1_frost_keypair keypairs[EXAMPLE_MAX_PARTICIPANTS];
    /* public_keys stores only public keys for each participant (this info can/should be shared among signers) */
    secp256k1_frost_pubkey public_keys[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_signature_share signature_shares[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_nonce *nonces[EXAMPLE_MAX_PARTICIPANTS];
    secp256k1_frost_nonce_commitment signing_commitments[EXAMPLE_MAX_PARTICIPANTS];

    /*** Initialization ***/
    sign_verify_ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

    /*** Key Generation ***/
    dealer_commitments = secp256k1_frost_vss_commitments_create(2);
    return_val = secp256k1_frost_keygen_with_dealer(sign_verify_ctx, dealer_commitments,
                                                shares_by_participant, keypairs,
                                                EXAMPLE_MAX_PARTICIPANTS, EXAMPLE_MIN_PARTICIPANTS);
    assert(return_val == 1);

    /* Extracting public_keys from keypair. This operation is intended to be executed by each signer.  */
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        secp256k1_frost_pubkey_from_keypair(&public_keys[index], &keypairs[index]);
    }

    /*** Signing ***/
    /* In FROST, each signer needs to generate a nonce for each signature to compute. A nonce commitment is
     * exchanged among signers to prevent forgery of signature aggregations. */

    /* Nonce:
     * Participants to the signing process generate a new nonce and share the related commitment */
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {

        /* Generate 32 bytes of randomness to use for computing the nonce. */
        if (!fill_random(binding_seed, sizeof(binding_seed))) {
            printf("Failed to generate binding_seed\n");
            return 1;
        }
        if (!fill_random(hiding_seed, sizeof(hiding_seed))) {
            printf("Failed to generate hiding_seed\n");
            return 1;
        }

        /* Create the nonce (the function already computes its commitment) */
        nonces[index] = secp256k1_frost_nonce_create(sign_verify_ctx, &keypairs[index],
                                                     binding_seed, hiding_seed);
        /* Copying secp256k1_frost_nonce_commitment to a shared array across participants */
        memcpy(&signing_commitments[index], &(nonces[index]->commitments), sizeof(secp256k1_frost_nonce_commitment));
    }

    /* Instead of signing (possibly very long) messages directly, we sign a 32-byte hash of the message.
     * We use secp256k1_tagged_sha256 to create this hash.  */
    return_val = secp256k1_tagged_sha256(sign_verify_ctx, msg_hash, tag, sizeof(tag), msg, sizeof(msg));
    assert(return_val == 1);

    /* Signature Share:
     * At least EXAMPLE_MIN_PARTICIPANTS participants compute a signature share. These
     * signature shares will be then aggregated to compute a single FROST signature. */
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        /* The secp256k1_frost_sign function provides a simple interface for signing 32-byte messages
         * (which in our case is a hash of the actual message).
         * Besides the message (msg_hash in this case), the function requires the number of other signers,
         * the private signer keypair and nonce, and the public signing commitments of other participants.
         */
        return_val = secp256k1_frost_sign(&(signature_shares[index]), msg_hash, EXAMPLE_MIN_PARTICIPANTS,
                             &keypairs[index], nonces[index], signing_commitments);
        assert(return_val == 1);
    }

    /*** Aggregation ***/

    /* A single entity can aggregate all signature shares. Otherwise, each participant can collect
     * and aggregate all signature shares by the other participants to the signing protocol.
     * We assume participant with index = 0 is aggregating the signature shares to compute the
     * FROST signature. */
    return_val = secp256k1_frost_aggregate(sign_verify_ctx, signature, msg_hash,
                                           &keypairs[0], public_keys, signing_commitments,
                                           signature_shares, EXAMPLE_MIN_PARTICIPANTS);
    assert(return_val == 1);

    /*** Verification ***/
    /* Verify a signature. This will return 1 if it's valid and 0 if it's not. */
    is_signature_valid = secp256k1_frost_verify(sign_verify_ctx, signature, msg_hash, &keypairs[0].public_keys);

    /* Print signature and participant keys */
    printf("Is the signature valid? %s\n", is_signature_valid ? "true" : "false");
    printf("Group Public Key: ");
    print_hex(keypairs[0].public_keys.group_public_key, sizeof(keypairs[0].public_keys.group_public_key));
    printf("Signature: ");
    print_hex(signature, sizeof(signature));
    printf("\n");
    for (index = 0; index < EXAMPLE_MAX_PARTICIPANTS; index++) {
        printf("Participant #%d: Secret Key: ", index);
        print_hex(keypairs[index].secret, sizeof(keypairs[index].secret));
        printf("Public Key: ");
        print_hex(keypairs[index].public_keys.public_key, sizeof(keypairs[index].public_keys.public_key));
    }

    /* This will clear everything from the context and free the memory */
    secp256k1_frost_vss_commitments_destroy(dealer_commitments);
    for (index = 0; index < EXAMPLE_MIN_PARTICIPANTS; index++) {
        secp256k1_frost_nonce_destroy(nonces[index]);
    }
    secp256k1_context_destroy(sign_verify_ctx);

    return 0;
}
