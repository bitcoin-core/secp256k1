/***********************************************************************
 * Copyright (c) 2018-2020 Andrew Poelstra, Jonas Nick                 *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_MAIN_H
#define SECP256K1_MODULE_SCHNORRSIG_MAIN_H

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_schnorrsig.h"
#include "../../hash.h"

static uint64_t s2c_opening_magic = 0x5d0520b8b7f2b168ULL;

static const unsigned char s2c_data_tag[16] = {
    's', '2', 'c', '/', 's', 'c', 'h', 'n', 'o', 'r', 'r', '/', 'd', 'a', 't', 'a'
};
static const unsigned char s2c_point_tag[17] = {
    's', '2', 'c', '/', 's', 'c', 'h', 'n', 'o', 'r', 'r', '/', 'p', 'o', 'i', 'n', 't'
};

static void secp256k1_schnorrsig_s2c_opening_init(secp256k1_schnorrsig_s2c_opening *opening) {
    opening->magic = s2c_opening_magic;
    opening->nonce_is_negated = 0;
}

static int secp256k1_schnorrsig_s2c_commit_is_init(const secp256k1_schnorrsig_s2c_opening *opening) {
    return opening->magic == s2c_opening_magic;
}

/* s2c_opening is serialized as 33 bytes containing the compressed original pubnonce. In addition to
 * holding the EVEN or ODD tag, the first byte has the third bit set to 1 if the nonce was negated.
 * The remaining bits in the first byte are 0. */
int secp256k1_schnorrsig_s2c_opening_parse(const secp256k1_context* ctx, secp256k1_schnorrsig_s2c_opening* opening, const unsigned char *input33) {
    unsigned char pk_ser[33];
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(opening != NULL);
    ARG_CHECK(input33 != NULL);

    secp256k1_schnorrsig_s2c_opening_init(opening);
    /* Return 0 if unknown bits are set */
    if ((input33[0] & ~0x06) != 0) {
        return 0;
    }
    /* Read nonce_is_negated bit */
    opening->nonce_is_negated = input33[0] & (1 << 2);
    memcpy(pk_ser, input33, sizeof(pk_ser));
    /* Unset nonce_is_negated bit to allow parsing the public key */
    pk_ser[0] &= ~(1 << 2);
    return secp256k1_ec_pubkey_parse(ctx, &opening->original_pubnonce, &pk_ser[0], 33);
}

int secp256k1_schnorrsig_s2c_opening_serialize(const secp256k1_context* ctx, unsigned char *output33, const secp256k1_schnorrsig_s2c_opening* opening) {
    size_t outputlen = 33;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(output33 != NULL);
    ARG_CHECK(opening != NULL);
    ARG_CHECK(secp256k1_schnorrsig_s2c_commit_is_init(opening));

    if (!secp256k1_ec_pubkey_serialize(ctx, &output33[0], &outputlen, &opening->original_pubnonce, SECP256K1_EC_COMPRESSED)) {
        return 0;
    }
    /* Verify that ec_pubkey_serialize only sets the first two bits of the
     * first byte, otherwise this function doesn't make any sense */
    VERIFY_CHECK(output33[0] == 0x02 || output33[0] == 0x03);
    if (opening->nonce_is_negated) {
        /* Set nonce_is_negated bit */
        output33[0] |= (1 << 2);
    }
    return 1;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/nonce")||SHA256("BIP0340/nonce"). */
static void secp256k1_nonce_function_bip340_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x46615b35ul;
    sha->s[1] = 0xf4bfbff7ul;
    sha->s[2] = 0x9f8dc671ul;
    sha->s[3] = 0x83627ab3ul;
    sha->s[4] = 0x60217180ul;
    sha->s[5] = 0x57358661ul;
    sha->s[6] = 0x21a29e54ul;
    sha->s[7] = 0x68b07b4cul;

    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/aux")||SHA256("BIP0340/aux"). */
static void secp256k1_nonce_function_bip340_sha256_tagged_aux(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x24dd3219ul;
    sha->s[1] = 0x4eba7e70ul;
    sha->s[2] = 0xca0fabb9ul;
    sha->s[3] = 0x0fa3166dul;
    sha->s[4] = 0x3afbe4b1ul;
    sha->s[5] = 0x4c44df97ul;
    sha->s[6] = 0x4aac2739ul;
    sha->s[7] = 0x249e850aul;

    sha->bytes = 64;
}

/* algo argument for nonce_function_bip340 to derive the nonce exactly as stated in BIP-340
 * by using the correct tagged hash function. */
static const unsigned char bip340_algo[] = {'B', 'I', 'P', '0', '3', '4', '0', '/', 'n', 'o', 'n', 'c', 'e'};

static const unsigned char schnorrsig_extraparams_magic_v0[4] = SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC_V0;
static const unsigned char schnorrsig_extraparams_magic_v1[4] = SECP256K1_SCHNORRSIG_EXTRAPARAMS_MAGIC_V1;

static int nonce_function_bip340(unsigned char *nonce32, const unsigned char *msg, size_t msglen, const unsigned char *key32, const unsigned char *xonly_pk32, const unsigned char *algo, size_t algolen, void *data) {
    secp256k1_sha256 sha;
    unsigned char masked_key[32];
    int i;

    if (algo == NULL) {
        return 0;
    }

    if (data != NULL) {
        secp256k1_nonce_function_bip340_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(&sha, data, 32);
        secp256k1_sha256_finalize(&sha, masked_key);
        for (i = 0; i < 32; i++) {
            masked_key[i] ^= key32[i];
        }
    } else {
        /* Precomputed TaggedHash("BIP0340/aux", 0x0000...00); */
        static const unsigned char ZERO_MASK[32] = {
              84, 241, 105, 207, 201, 226, 229, 114,
             116, 128,  68,  31, 144, 186,  37, 196,
             136, 244,  97, 199,  11,  94, 165, 220,
             170, 247, 175, 105, 39,  10, 165,  20
        };
        for (i = 0; i < 32; i++) {
            masked_key[i] = key32[i] ^ ZERO_MASK[i];
        }
    }

    /* Tag the hash with algo which is important to avoid nonce reuse across
     * algorithms. If this nonce function is used in BIP-340 signing as defined
     * in the spec, an optimized tagging implementation is used. */
    if (algolen == sizeof(bip340_algo)
            && secp256k1_memcmp_var(algo, bip340_algo, algolen) == 0) {
        secp256k1_nonce_function_bip340_sha256_tagged(&sha);
    } else {
        secp256k1_sha256_initialize_tagged(&sha, algo, algolen);
    }

    /* Hash masked-key||pk||msg using the tagged hash as per the spec */
    secp256k1_sha256_write(&sha, masked_key, 32);
    secp256k1_sha256_write(&sha, xonly_pk32, 32);
    secp256k1_sha256_write(&sha, msg, msglen);
    secp256k1_sha256_finalize(&sha, nonce32);
    return 1;
}

const secp256k1_nonce_function_hardened secp256k1_nonce_function_bip340 = nonce_function_bip340;

/* Initializes SHA256 with fixed midstate. This midstate was computed by applying
 * SHA256 to SHA256("BIP0340/challenge")||SHA256("BIP0340/challenge"). */
static void secp256k1_schnorrsig_sha256_tagged(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x9cecba11ul;
    sha->s[1] = 0x23925381ul;
    sha->s[2] = 0x11679112ul;
    sha->s[3] = 0xd1627e0ful;
    sha->s[4] = 0x97c87550ul;
    sha->s[5] = 0x003cc765ul;
    sha->s[6] = 0x90f61164ul;
    sha->s[7] = 0x33e9b66aul;
    sha->bytes = 64;
}

static void secp256k1_schnorrsig_challenge(secp256k1_scalar* e, const unsigned char *r32, const unsigned char *msg, size_t msglen, const unsigned char *pubkey32)
{
    unsigned char buf[32];
    secp256k1_sha256 sha;

    /* tagged hash(r.x, pk.x, msg) */
    secp256k1_schnorrsig_sha256_tagged(&sha);
    secp256k1_sha256_write(&sha, r32, 32);
    secp256k1_sha256_write(&sha, pubkey32, 32);
    secp256k1_sha256_write(&sha, msg, msglen);
    secp256k1_sha256_finalize(&sha, buf);
    /* Set scalar e to the challenge hash modulo the curve order as per
     * BIP340. */
    secp256k1_scalar_set_b32(e, buf, NULL);
}

static int secp256k1_schnorrsig_sign_internal(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_keypair *keypair, secp256k1_nonce_function_hardened noncefp, void *ndata, secp256k1_schnorrsig_s2c_opening *s2c_opening, const unsigned char *s2c_data32) {
    secp256k1_scalar sk;
    secp256k1_scalar e;
    secp256k1_scalar k;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_ge r;
    secp256k1_sha256 sha;
    unsigned char buf[32] = { 0 };
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    unsigned char noncedata[32];
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(keypair != NULL);
    /* sign-to-contract commitments only work with the default nonce function,
     * because we need to ensure that s2c_data is actually hashed into the nonce and
     * not just ignored because otherwise this could result in nonce reuse. */
    ARG_CHECK(s2c_data32 == NULL || (noncefp == NULL || noncefp == secp256k1_nonce_function_bip340));
    /* s2c_opening and s2c_data32 should be either both non-NULL or both NULL. */
    ARG_CHECK((s2c_opening != NULL) == (s2c_data32 != NULL));

    if (noncefp == NULL) {
        noncefp = secp256k1_nonce_function_bip340;
    }

    ret &= secp256k1_keypair_load(ctx, &sk, &pk, keypair);
    /* Because we are signing for a x-only pubkey, the secret key is negated
     * before signing if the point corresponding to the secret key does not
     * have an even Y. */
    if (secp256k1_fe_is_odd(&pk.y)) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    secp256k1_scalar_get_b32(seckey, &sk);
    secp256k1_fe_get_b32(pk_buf, &pk.x);

    if (s2c_data32 != NULL) {
        /* Provide s2c_data32 and ndata (if not NULL) to the the nonce function
         * as additional data to derive the nonce from. If both pointers are
         * not NULL, they need to be hashed to get the nonce data 32 bytes.
         * Even if only s2c_data32 is not NULL, it's hashed because it should
         * be possible to derive nonces even if only a SHA256 commitment to the
         * data is known. This is for example important in the anti nonce
         * sidechannel protocol.
         */
        secp256k1_sha256_initialize_tagged(&sha, s2c_data_tag, sizeof(s2c_data_tag));
        secp256k1_sha256_write(&sha, s2c_data32, 32);
        if (ndata != NULL) {
            secp256k1_sha256_write(&sha, ndata, 32);
        }
        secp256k1_sha256_finalize(&sha, noncedata);
        ndata = &noncedata;
    }

    ret &= !!noncefp(buf, msg, msglen, seckey, pk_buf, bip340_algo, sizeof(bip340_algo), ndata);
    secp256k1_scalar_set_b32(&k, buf, NULL);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej(&r, &rj);

    if (s2c_opening != NULL) {
        secp256k1_schnorrsig_s2c_opening_init(s2c_opening);
        if (s2c_data32 != NULL) {
            secp256k1_sha256_initialize_tagged(&sha, s2c_point_tag, sizeof(s2c_point_tag));
            /* Create sign-to-contract commitment */
            secp256k1_pubkey_save(&s2c_opening->original_pubnonce, &r);
            secp256k1_ec_commit_seckey(&k, &r, &sha, s2c_data32, 32);
            secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
            secp256k1_ge_set_gej(&r, &rj);
        }
    }

    /* We declassify r to allow using it as a branch point. This is fine
     * because r is not a secret. */
    secp256k1_declassify(ctx, &r, sizeof(r));
    secp256k1_fe_normalize_var(&r.y);
    if (secp256k1_fe_is_odd(&r.y)) {
        secp256k1_scalar_negate(&k, &k);
        if (s2c_opening != NULL) {
            s2c_opening->nonce_is_negated = 1;
        }
    }
    secp256k1_fe_normalize_var(&r.x);
    secp256k1_fe_get_b32(&sig64[0], &r.x);

    secp256k1_schnorrsig_challenge(&e, &sig64[0], msg, msglen, pk_buf);
    secp256k1_scalar_mul(&e, &e, &sk);
    secp256k1_scalar_add(&e, &e, &k);
    secp256k1_scalar_get_b32(&sig64[32], &e);

    secp256k1_memczero(sig64, 64, !ret);
    secp256k1_scalar_clear(&k);
    secp256k1_scalar_clear(&sk);
    memset(seckey, 0, sizeof(seckey));

    return ret;
}

int secp256k1_schnorrsig_sign32(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg32, const secp256k1_keypair *keypair, const unsigned char *aux_rand32) {
    /* We cast away const from the passed aux_rand32 argument since we know the default nonce function does not modify it. */
    return secp256k1_schnorrsig_sign_internal(ctx, sig64, msg32, 32, keypair, secp256k1_nonce_function_bip340, (unsigned char*)aux_rand32, NULL, NULL);
}

int secp256k1_schnorrsig_sign(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg32, const secp256k1_keypair *keypair, const unsigned char *aux_rand32) {
    return secp256k1_schnorrsig_sign32(ctx, sig64, msg32, keypair, aux_rand32);
}

int secp256k1_schnorrsig_sign_custom(const secp256k1_context* ctx, unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_keypair *keypair, secp256k1_schnorrsig_extraparams *extraparams) {
    secp256k1_nonce_function_hardened noncefp = NULL;
    void *ndata = NULL;
    secp256k1_schnorrsig_s2c_opening *s2c_opening = NULL;
    const unsigned char *s2c_data32 = NULL;
    VERIFY_CHECK(ctx != NULL);

    if (extraparams != NULL) {
        ARG_CHECK(secp256k1_memcmp_var(extraparams->magic,
                                       schnorrsig_extraparams_magic_v0,
                                       sizeof(extraparams->magic)) == 0 ||
                  secp256k1_memcmp_var(extraparams->magic,
                                       schnorrsig_extraparams_magic_v1,
                                       sizeof(extraparams->magic)) == 0);
        noncefp = extraparams->noncefp;
        ndata = extraparams->ndata;
        if (secp256k1_memcmp_var(extraparams->magic,
                                 schnorrsig_extraparams_magic_v1,
                                 sizeof(extraparams->magic)) == 0) {
            s2c_opening = extraparams->s2c_opening;
            s2c_data32 = extraparams->s2c_data32;
        }
    }
    return secp256k1_schnorrsig_sign_internal(ctx, sig64, msg, msglen, keypair, noncefp, ndata, s2c_opening, s2c_data32);
}

int secp256k1_schnorrsig_verify(const secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *pubkey) {
    secp256k1_scalar s;
    secp256k1_scalar e;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_gej pkj;
    secp256k1_fe rx;
    secp256k1_ge r;
    unsigned char buf[32];
    int overflow;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(pubkey != NULL);

    if (!secp256k1_fe_set_b32_limit(&rx, &sig64[0])) {
        return 0;
    }

    secp256k1_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }

    if (!secp256k1_xonly_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    /* Compute e. */
    secp256k1_fe_get_b32(buf, &pk.x);
    secp256k1_schnorrsig_challenge(&e, &sig64[0], msg, msglen, buf);

    /* Compute rj =  s*G + (-e)*pkj */
    secp256k1_scalar_negate(&e, &e);
    secp256k1_gej_set_ge(&pkj, &pk);
    secp256k1_ecmult(&rj, &pkj, &e, &s);

    secp256k1_ge_set_gej_var(&r, &rj);
    if (secp256k1_ge_is_infinity(&r)) {
        return 0;
    }

    secp256k1_fe_normalize_var(&r.y);
    return !secp256k1_fe_is_odd(&r.y) &&
           secp256k1_fe_equal(&rx, &r.x);
}

int secp256k1_schnorrsig_verify_s2c_commit(const secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *data32, const secp256k1_schnorrsig_s2c_opening *opening) {
    secp256k1_fe rx;
    secp256k1_ge original_r;
    secp256k1_ge r;
    secp256k1_sha256 sha;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(data32 != NULL);
    ARG_CHECK(opening != NULL);
    ARG_CHECK(secp256k1_schnorrsig_s2c_commit_is_init(opening));

    if (!secp256k1_fe_set_b32_limit(&rx, &sig64[0])) {
        return 0;
    }
    if (!secp256k1_ge_set_xo_var(&r, &rx, 0)) {
        return 0;
    }
    if (opening->nonce_is_negated) {
        secp256k1_ge_neg(&r, &r);
    }

    if (!secp256k1_pubkey_load(ctx, &original_r, &opening->original_pubnonce)) {
        return 0;
    }

    secp256k1_sha256_initialize_tagged(&sha, s2c_point_tag, sizeof(s2c_point_tag));
    return secp256k1_ec_commit_verify(&r, &original_r, &sha, data32, 32);
}

int secp256k1_schnorrsig_anti_exfil_host_commit(const secp256k1_context* ctx, unsigned char* rand_commitment32, const unsigned char* rand32) {
    secp256k1_sha256 sha;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(rand_commitment32 != NULL);
    ARG_CHECK(rand32 != NULL);

    secp256k1_sha256_initialize_tagged(&sha, s2c_data_tag, sizeof(s2c_data_tag));
    secp256k1_sha256_write(&sha, rand32, 32);
    secp256k1_sha256_finalize(&sha, rand_commitment32);

    return 1;
}

int secp256k1_schnorrsig_anti_exfil_signer_commit(const secp256k1_context* ctx, secp256k1_schnorrsig_anti_exfil_signer_commitment* signer_commitment, const unsigned char *msg, size_t msglen, const secp256k1_keypair *keypair, const unsigned char* rand_commitment32) {
    secp256k1_scalar sk;
    secp256k1_scalar k;
    secp256k1_gej rj;
    secp256k1_ge pk;
    secp256k1_ge r;
    unsigned char buf[32] = { 0 };
    unsigned char pk_buf[32];
    unsigned char seckey[32];
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    ARG_CHECK(msg != NULL || msglen == 0);
    ARG_CHECK(keypair != NULL);

    ret &= secp256k1_keypair_load(ctx, &sk, &pk, keypair);
    /* Because we are signing for a x-only pubkey, the secret key is negated
     * before signing if the point corresponding to the secret key does not
     * have an even Y. */
    if (secp256k1_fe_is_odd(&pk.y)) {
        secp256k1_scalar_negate(&sk, &sk);
    }

    secp256k1_scalar_get_b32(seckey, &sk);
    secp256k1_fe_get_b32(pk_buf, &pk.x);

    ret &= !!secp256k1_nonce_function_bip340(buf, msg, msglen, seckey, pk_buf, bip340_algo, sizeof(bip340_algo), (void*)rand_commitment32);
    secp256k1_scalar_set_b32(&k, buf, NULL);
    ret &= !secp256k1_scalar_is_zero(&k);
    secp256k1_scalar_cmov(&k, &secp256k1_scalar_one, !ret);

    secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &rj, &k);
    secp256k1_ge_set_gej(&r, &rj);

    secp256k1_pubkey_save(signer_commitment, &r);

    return ret;
}

int secp256k1_schnorrsig_anti_exfil_host_verify(const secp256k1_context* ctx, const unsigned char *sig64, const unsigned char *msg, size_t msglen, const secp256k1_xonly_pubkey *pubkey, const unsigned char *host_data32, const secp256k1_schnorrsig_anti_exfil_signer_commitment *signer_commitment, const secp256k1_schnorrsig_s2c_opening *opening) {
    /* Verify that the signer commitment matches the opening made when signing */
    if (secp256k1_ec_pubkey_cmp(ctx, signer_commitment, &opening->original_pubnonce)) {
        return 0;
    }
    /* Verify signature */
    if (!secp256k1_schnorrsig_verify(ctx, sig64, msg, msglen, pubkey)) {
        return 0;
    }
    /* Verify that the host nonce contribution was committed to */
    return secp256k1_schnorrsig_verify_s2c_commit(ctx, sig64, host_data32, opening);
}

#endif
