/*************************************************************************
 * To the extent possible under law, the author(s) have dedicated all    *
 * copyright and related and neighboring rights to the software in this  *
 * file to the public domain worldwide. This software is distributed     *
 * without any warranty. For the CC0 Public Domain Dedication, see       *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

/** This file demonstrates how to use the recovery module to create a
  * recoverable ECDSA signature and extract the corresponding
  * public key from it.
  */

#include <stdio.h>
#include <stdlib.h>
#include <assert.h>
#include <string.h>

#include <secp256k1.h>
#include <secp256k1_recovery.h>

#include "examples_util.h"

int main(void) {
    unsigned char msg[32] = "this_could_be_the_hash_of_a_msg";
    unsigned char seckey[32];
    unsigned char randomize[32];
    unsigned char recoverable_sig_ser[64];
    unsigned char serialized_pubkey[33];
    unsigned char serialized_recovered_pubkey[33];
    size_t len;
    int return_val, recovery_id;
    secp256k1_pubkey pubkey, recovered_pubkey;
    secp256k1_ecdsa_recoverable_signature recoverable_sig;
    secp256k1_ecdsa_signature normal_sig;

    /* Before we can call actual API functions, we need to create a "context". */
    secp256k1_context* ctx = secp256k1_context_create(SECP256K1_CONTEXT_NONE);
    if (!fill_random(randomize, sizeof(randomize))) {
        printf("Failed to generate randomness\n");
        return EXIT_FAILURE;
    }
    /* Randomizing the context is recommended to protect against side-channel
     * leakage. See `secp256k1_context_randomize` in secp256k1.h for more
     * information about it. This should never fail. */
    return_val = secp256k1_context_randomize(ctx, randomize);
    assert(return_val);

    /*** Key Generation ***/
    if (!fill_random(seckey, sizeof(seckey))) {
        printf("Failed to generate randomness\n");
        return EXIT_FAILURE;
    }
    /* Try to create a public key with a valid context. This only fails if the
     * secret key is zero or out of range (greater than secp256k1's order). Note
     * that the probability of this occurring is negligible with a properly
     * functioning random number generator. */
    if (!secp256k1_ec_pubkey_create(ctx, &pubkey, seckey)) {
        printf("Generated secret key is invalid. This indicates an issue with the random number generator.\n");
        return EXIT_FAILURE;
    }

    /* Serialize the public key. Should always return 1 for a valid public key. */
    len = sizeof(serialized_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, serialized_pubkey, &len, &pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    /*** Signing ***/

    /* Signing with a valid context, verified secret key
     * and the default nonce function should never fail. */
    return_val = secp256k1_ecdsa_sign_recoverable(ctx, &recoverable_sig, msg, seckey, NULL, NULL);
    assert(return_val);

    /* Serialize in compact format (64 bytes + recovery id integer) */
    return_val = secp256k1_ecdsa_recoverable_signature_serialize_compact(ctx,
        recoverable_sig_ser, &recovery_id, &recoverable_sig);
    assert(return_val);

    /*** Public key recovery / verification ***/

    /* Deserialize the recoverable signature. This will return 0 if the signature can't be parsed correctly. */
    if (!secp256k1_ecdsa_recoverable_signature_parse_compact(ctx, &recoverable_sig, recoverable_sig_ser, recovery_id)) {
        printf("Failed parsing the recoverable signature\n");
        return EXIT_FAILURE;
    }

    /* Recover the public key */
    if (!secp256k1_ecdsa_recover(ctx, &recovered_pubkey, &recoverable_sig, msg)) {
        printf("Public key recovery failed\n");
        return EXIT_FAILURE;
    }
    len = sizeof(serialized_recovered_pubkey);
    return_val = secp256k1_ec_pubkey_serialize(ctx, serialized_recovered_pubkey,
        &len, &recovered_pubkey, SECP256K1_EC_COMPRESSED);
    assert(return_val);

    /* Successful recovery guarantees a correct signature, but we also do an explicit verification
       to demonstrate how to convert a recoverable to a normal ECDSA signature */
    return_val = secp256k1_ecdsa_recoverable_signature_convert(ctx, &normal_sig, &recoverable_sig);
    assert(return_val);
    /* A converted recoverable signature doesn't necessarily follow the lower-S rule that is required
     * to pass `secp256k1_ecdsa_verify`, so we have to normalize it first (note that in this specific
     * example that's a no-op, as `secp256k1_ecdsa_sign_recoverable` always creates lower-S signatures,
     * but in general the verifier is a different entity and can't rely on that) */
    secp256k1_ecdsa_signature_normalize(ctx, &normal_sig, &normal_sig);
    if (!secp256k1_ecdsa_verify(ctx, &normal_sig, msg, &recovered_pubkey)) {
        printf("Signature verification with converted recoverable signature failed\n");
        return EXIT_FAILURE;
    }

    /* Actual public key and recovered public key should match */
    return_val = memcmp(serialized_pubkey, serialized_recovered_pubkey, sizeof(serialized_pubkey));
    assert(return_val == 0);

    printf("     Secret Key: ");
    print_hex(seckey, sizeof(seckey));
    printf("     Public Key: ");
    print_hex(serialized_pubkey, sizeof(serialized_pubkey));
    printf(" Rec. signature: ");
    print_hex(recoverable_sig_ser, sizeof(recoverable_sig_ser));
    printf("    Recovery id: %d\n", recovery_id);
    printf("Rec. public key: ");
    print_hex(serialized_recovered_pubkey, sizeof(serialized_recovered_pubkey));

    /* This will clear everything from the context and free the memory */
    secp256k1_context_destroy(ctx);

    /* It's best practice to try to clear secrets from memory after using them.
     * This is done because some bugs can allow an attacker to leak memory, for
     * example through "out of bounds" array access (see Heartbleed), or the OS
     * swapping them to disk. Hence, we overwrite the secret key buffer with zeros.
     *
     * Here we are preventing these writes from being optimized out, as any good compiler
     * will remove any writes that aren't used. */
    secure_erase(seckey, sizeof(seckey));

    return EXIT_SUCCESS;
}
