#ifndef SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H
#define SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H

struct agent {
    secp256k1_pubkey left_lock;
    secp256k1_pubkey right_lock;
    /* adaptor secret for right_lock - left_lock */
    unsigned char adaptor_secret[32];
    secp256k1_pubkey pubkey;
    unsigned char secret[32];
};

void multi_hop_lock_test(void) {
    /* TODO: initialize */
    struct agent Sender;
    struct agent Intermediate;
    struct agent Receiver;

    /* TODO everything */
}

void run_ecdsa_adaptor_tests(void) {

}

#endif /* SECP256K1_MODULE_ECDSA_ADAPTOR_TESTS_H */


