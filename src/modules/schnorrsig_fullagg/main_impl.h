/***********************************************************************
 * Copyright (c) 2025 Fabian Jahr                                      *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_MODULE_SCHNORRSIG_FULLAGG_MAIN_H
#define SECP256K1_MODULE_SCHNORRSIG_FULLAGG_MAIN_H

#include <string.h>

#include "../../../include/secp256k1.h"
#include "../../../include/secp256k1_extrakeys.h"
#include "../../../include/secp256k1_schnorrsig_fullagg.h"

#include "../../eckey.h"
#include "../../group.h"
#include "../../hash.h"
#include "../../scalar.h"
#include "../../util.h"

static const unsigned char secp256k1_fullagg_secnonce_magic[4] = { 0xf1, 0x1a, 0x99, 0x01 };

/* TODO: Share with MuSig */
static void secp256k1_fullagg_secnonce_save(secp256k1_fullagg_secnonce *secnonce, const secp256k1_scalar *k, const secp256k1_ge *pk) {
    memcpy(&secnonce->data[0], secp256k1_fullagg_secnonce_magic, 4);

    secp256k1_scalar_get_b32(&secnonce->data[4], &k[0]);
    secp256k1_scalar_get_b32(&secnonce->data[36], &k[1]);
    secp256k1_ge_to_bytes(&secnonce->data[68], pk);
}

/* TODO: Share with MuSig */
static int secp256k1_fullagg_secnonce_load(const secp256k1_context* ctx, secp256k1_scalar *k, secp256k1_ge *pk, const secp256k1_fullagg_secnonce *secnonce) {
    int is_zero;

    ARG_CHECK(secp256k1_memcmp_var(&secnonce->data[0], secp256k1_fullagg_secnonce_magic, 4) == 0);
    /* We make very sure that the nonce isn't invalidated by checking the values
     * in addition to the magic. */
    is_zero = secp256k1_is_zero_array(&secnonce->data[4], 2 * 32);
    secp256k1_declassify(ctx, &is_zero, sizeof(is_zero));
    ARG_CHECK(!is_zero);

    secp256k1_scalar_set_b32(&k[0], &secnonce->data[4], NULL);
    secp256k1_scalar_set_b32(&k[1], &secnonce->data[36], NULL);
    secp256k1_ge_from_bytes(pk, &secnonce->data[68]);
    return 1;
}

/* TODO: Share with MuSig */
/* If flag is true, invalidate the secnonce; otherwise leave it. Constant-time. */
static void secp256k1_fullagg_secnonce_invalidate(const secp256k1_context* ctx, secp256k1_fullagg_secnonce *secnonce, int flag) {
    secp256k1_memczero(secnonce->data, sizeof(secnonce->data), flag);
    /* The flag argument is usually classified. So, the line above makes the
     * magic and public key classified. However, we need both to be
     * declassified. Note that we don't declassify the entire object, because if
     * flag is 0, then k[0] and k[1] have not been zeroed. */
    secp256k1_declassify(ctx, secnonce->data, sizeof(secp256k1_fullagg_secnonce_magic));
    secp256k1_declassify(ctx, &secnonce->data[68], 64);
}

static const unsigned char secp256k1_fullagg_pubnonce_magic[4] = { 0xf1, 0x1a, 0x99, 0x02 };

/* TODO: Share with MuSig */
/* Saves two group elements into a pubnonce. */
static void secp256k1_fullagg_pubnonce_save(secp256k1_fullagg_pubnonce* nonce, const secp256k1_ge* ges) {
    int i;

    memcpy(&nonce->data[0], secp256k1_fullagg_pubnonce_magic, 4);
    for (i = 0; i < 2; i++) {
        secp256k1_ge_to_bytes(nonce->data + 4 + 64*i, &ges[i]);
    }
}

/* TODO: Share with MuSig */
/* Loads two group elements from a pubnonce. */
static int secp256k1_fullagg_pubnonce_load(const secp256k1_context* ctx, secp256k1_ge* ges, const secp256k1_fullagg_pubnonce* nonce) {
    int i;

    ARG_CHECK(secp256k1_memcmp_var(&nonce->data[0], secp256k1_fullagg_pubnonce_magic, 4) == 0);
    for (i = 0; i < 2; i++) {
        secp256k1_ge_from_bytes(&ges[i], nonce->data + 4 + 64*i);
    }
    return 1;
}

static const unsigned char secp256k1_fullagg_aggnonce_magic[4] = { 0xf1, 0x1a, 0x99, 0x03 };

/* TODO: Share with MuSig */
/* Save aggregate nonce */
static void secp256k1_fullagg_aggnonce_save(secp256k1_fullagg_aggnonce* nonce, const secp256k1_ge* ges) {
    int i;

    memcpy(&nonce->data[0], secp256k1_fullagg_aggnonce_magic, 4);
    for (i = 0; i < 2; i++) {
        secp256k1_ge_to_bytes_ext(&nonce->data[4 + 64*i], &ges[i]);
    }
}

/* TODO: Share with MuSig */
/* Load aggregate nonce */
static int secp256k1_fullagg_aggnonce_load(const secp256k1_context* ctx, secp256k1_ge* ges, const secp256k1_fullagg_aggnonce* nonce) {
    int i;

    ARG_CHECK(secp256k1_memcmp_var(&nonce->data[0], secp256k1_fullagg_aggnonce_magic, 4) == 0);
    for (i = 0; i < 2; i++) {
        secp256k1_ge_from_bytes_ext(&ges[i], &nonce->data[4 + 64*i]);
    }
    return 1;
}

static const unsigned char secp256k1_fullagg_partial_sig_magic[4] = { 0xf1, 0x1a, 0x99, 0x05 };

/* TODO: Share with MuSig */
/* Save partial signature */
static void secp256k1_fullagg_partial_sig_save(secp256k1_fullagg_partial_sig* sig, secp256k1_scalar *s) {
    memcpy(&sig->data[0], secp256k1_fullagg_partial_sig_magic, 4);
    secp256k1_scalar_get_b32(&sig->data[4], s);
}

/* TODO: Share with MuSig */
/* Load partial signature */
static int secp256k1_fullagg_partial_sig_load(const secp256k1_context* ctx, secp256k1_scalar *s, const secp256k1_fullagg_partial_sig* sig) {
    int overflow;

    ARG_CHECK(secp256k1_memcmp_var(&sig->data[0], secp256k1_fullagg_partial_sig_magic, 4) == 0);
    secp256k1_scalar_set_b32(s, &sig->data[4], &overflow);
    /* Parsed signatures can not overflow */
    VERIFY_CHECK(!overflow);
    return 1;
}

/* TODO: Share with MuSig */
/* Parse/serialize functions for public interface */
int secp256k1_fullagg_pubnonce_parse(const secp256k1_context* ctx, secp256k1_fullagg_pubnonce* nonce, const unsigned char *in66) {
    secp256k1_ge ges[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(in66 != NULL);

    for (i = 0; i < 2; i++) {
        if (!secp256k1_eckey_pubkey_parse(&ges[i], &in66[33*i], 33)) {
            return 0;
        }
        if (!secp256k1_ge_is_in_correct_subgroup(&ges[i])) {
            return 0;
        }
    }
    secp256k1_fullagg_pubnonce_save(nonce, ges);
    return 1;
}

/* TODO: Share with MuSig */
int secp256k1_fullagg_pubnonce_serialize(const secp256k1_context* ctx, unsigned char *out66, const secp256k1_fullagg_pubnonce* nonce) {
    secp256k1_ge ges[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out66 != NULL);
    ARG_CHECK(nonce != NULL);
    memset(out66, 0, 66);

    if (!secp256k1_fullagg_pubnonce_load(ctx, ges, nonce)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        secp256k1_eckey_pubkey_serialize33(&ges[i], &out66[33*i]);
    }
    return 1;
}

/* TODO: Share with MuSig */
int secp256k1_fullagg_aggnonce_parse(const secp256k1_context* ctx, secp256k1_fullagg_aggnonce* nonce, const unsigned char *in66) {
    secp256k1_ge ges[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(nonce != NULL);
    ARG_CHECK(in66 != NULL);

    for (i = 0; i < 2; i++) {
        if (!secp256k1_eckey_parse_ext(&ges[i], &in66[33*i])) {
            return 0;
        }
    }
    secp256k1_fullagg_aggnonce_save(nonce, ges);
    return 1;
}

/* TODO: Share with MuSig */
int secp256k1_fullagg_aggnonce_serialize(const secp256k1_context* ctx, unsigned char *out66, const secp256k1_fullagg_aggnonce* nonce) {
    secp256k1_ge ges[2];
    int i;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out66 != NULL);
    ARG_CHECK(nonce != NULL);
    memset(out66, 0, 66);

    if (!secp256k1_fullagg_aggnonce_load(ctx, ges, nonce)) {
        return 0;
    }
    for (i = 0; i < 2; i++) {
        secp256k1_eckey_serialize_ext(&out66[33*i], &ges[i]);
    }
    return 1;
}

/* TODO: Share with MuSig */
int secp256k1_fullagg_partial_sig_parse(const secp256k1_context* ctx, secp256k1_fullagg_partial_sig* sig, const unsigned char *in32) {
    secp256k1_scalar tmp;
    int overflow;
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(in32 != NULL);

    memset(sig, 0, sizeof(*sig));

    secp256k1_scalar_set_b32(&tmp, in32, &overflow);
    if (overflow) {
        return 0;
    }
    secp256k1_fullagg_partial_sig_save(sig, &tmp);
    return 1;
}

/* TODO: Share with MuSig */
int secp256k1_fullagg_partial_sig_serialize(const secp256k1_context* ctx, unsigned char *out32, const secp256k1_fullagg_partial_sig* sig) {
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(out32 != NULL);
    ARG_CHECK(sig != NULL);
    ARG_CHECK(secp256k1_memcmp_var(&sig->data[0], secp256k1_fullagg_partial_sig_magic, 4) == 0);

    memcpy(out32, &sig->data[4], 32);
    return 1;
}

/* Initializes SHA256 with fixed midstate for "FullAgg/aux" */
static void secp256k1_fullagg_sha256_tagged_aux(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x4cb4139bul;
    sha->s[1] = 0xac6dd715ul;
    sha->s[2] = 0x46eb898bul;
    sha->s[3] = 0xc13797e2ul;
    sha->s[4] = 0xa7c1aea6ul;
    sha->s[5] = 0x21aab077ul;
    sha->s[6] = 0x6f1746b2ul;
    sha->s[7] = 0x5c2bedd8ul;
    sha->bytes = 64;
}

/* Initializes SHA256 with fixed midstate for "FullAgg/nonce" */
static void secp256k1_fullagg_sha256_tagged_nonce(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0x742a20a9ul;
    sha->s[1] = 0x2c939aaeul;
    sha->s[2] = 0xf8f0f6c0ul;
    sha->s[3] = 0x9b975422ul;
    sha->s[4] = 0xbf5a4f08ul;
    sha->s[5] = 0xe5fa99eeul;
    sha->s[6] = 0xa64c241ful;
    sha->s[7] = 0x5b12ebccul;
    sha->bytes = 64;
}

/* FullAgg nonce generation function */
static void secp256k1_fullagg_nonce_function(secp256k1_scalar *k, const unsigned char *session_secrand, 
                                             const unsigned char *msg32, const unsigned char *seckey32, 
                                             const unsigned char *pk33, const unsigned char *extra_input32) {
    secp256k1_sha256 sha;
    unsigned char rand[32];
    unsigned char i;

    /* Bind nonce to secret key if it was provided, otherwise use secrand directly. */
    if (seckey32 != NULL) {
        secp256k1_fullagg_sha256_tagged_aux(&sha);
        secp256k1_sha256_write(&sha, session_secrand, 32);
        secp256k1_sha256_finalize(&sha, rand);
        for (i = 0; i < 32; i++) {
            rand[i] ^= seckey32[i];
        }
    } else {
        memcpy(rand, session_secrand, sizeof(rand));
    }

    /* Write all relevant data into hash for nonce. */
    secp256k1_fullagg_sha256_tagged_nonce(&sha);
    secp256k1_sha256_write(&sha, rand, sizeof(rand));
    secp256k1_sha256_write(&sha, pk33, 33);
    if (msg32 != NULL) {
        secp256k1_sha256_write(&sha, msg32, 32);
    }
    if (extra_input32 != NULL) {
        secp256k1_sha256_write(&sha, extra_input32, 32);
    }

    /* Generate the two nonces. */
    for (i = 0; i < 2; i++) {
        unsigned char buf[32];
        secp256k1_sha256 sha_tmp = sha;
        secp256k1_sha256_write(&sha_tmp, &i, 1);
        secp256k1_sha256_finalize(&sha_tmp, buf);
        secp256k1_scalar_set_b32(&k[i], buf, NULL);

        secp256k1_memclear_explicit(buf, sizeof(buf));
        secp256k1_sha256_clear(&sha_tmp);
    }
    secp256k1_memclear_explicit(rand, sizeof(rand));
    secp256k1_sha256_clear(&sha);
}

/* Internal nonce generation */
static int secp256k1_fullagg_nonce_gen_internal(const secp256k1_context* ctx, secp256k1_fullagg_secnonce *secnonce, 
                                                secp256k1_fullagg_pubnonce *pubnonce, const unsigned char *input_nonce,
                                                const unsigned char *seckey, const secp256k1_pubkey *pubkey,
                                                const unsigned char *msg32, const unsigned char *extra_input32) {
    secp256k1_scalar k[2];
    secp256k1_ge nonce_pts[2];
    secp256k1_gej nonce_ptj[2];
    int i;
    unsigned char pk_ser[33];
    secp256k1_ge pk;
    int ret = 1;

    ARG_CHECK(pubnonce != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(secp256k1_ecmult_gen_context_is_built(&ctx->ecmult_gen_ctx));
    memset(pubnonce, 0, sizeof(*pubnonce));

    /* Check that the seckey is valid to be able to sign for it later. */
    if (seckey != NULL) {
        secp256k1_scalar sk;
        ret &= secp256k1_scalar_set_b32_seckey(&sk, seckey);
        secp256k1_scalar_clear(&sk);
    }

    if (!secp256k1_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }
    secp256k1_eckey_pubkey_serialize33(&pk, pk_ser);

    /* Get secret nonce */
    secp256k1_fullagg_nonce_function(k, input_nonce, msg32, seckey, pk_ser, extra_input32);
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&k[0]));
    VERIFY_CHECK(!secp256k1_scalar_is_zero(&k[1]));
    secp256k1_fullagg_secnonce_save(secnonce, k, &pk);
    secp256k1_fullagg_secnonce_invalidate(ctx, secnonce, !ret);

    /* Compute pubnonce as R1_i = k[0]*G, R2_i = k[1]*G */
    for (i = 0; i < 2; i++) {
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &nonce_ptj[i], &k[i]);
        secp256k1_scalar_clear(&k[i]);
    }

    /* Convert pubnonce from jacobian to affine and mark as non-secret */
    secp256k1_ge_set_all_gej_var(nonce_pts, nonce_ptj, 2);
    for (i = 0; i < 2; i++) {
        secp256k1_gej_clear(&nonce_ptj[i]);
        secp256k1_declassify(ctx, &nonce_pts[i], sizeof(nonce_pts[i]));
    }
    
    secp256k1_fullagg_pubnonce_save(pubnonce, nonce_pts);
    return ret;
}

int secp256k1_fullagg_nonce_gen(const secp256k1_context* ctx, secp256k1_fullagg_secnonce *secnonce,
                                secp256k1_fullagg_pubnonce *pubnonce, unsigned char *session_secrand32,
                                const unsigned char *seckey, const secp256k1_pubkey *pubkey,
                                const unsigned char *msg32, const unsigned char *extra_input32) {
    int ret = 1;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secnonce != NULL);
    ARG_CHECK(session_secrand32 != NULL);
    memset(secnonce, 0, sizeof(*secnonce));

    ret &= !secp256k1_is_zero_array(session_secrand32, 32);
    secp256k1_declassify(ctx, &ret, sizeof(ret));
    if (ret == 0) {
        secp256k1_fullagg_secnonce_invalidate(ctx, secnonce, 1);
        return 0;
    }

    ret &= secp256k1_fullagg_nonce_gen_internal(ctx, secnonce, pubnonce, session_secrand32, 
                                                seckey, pubkey, msg32, extra_input32);
    secp256k1_memczero(session_secrand32, 32, ret);
    return ret;
}

int secp256k1_fullagg_nonce_gen_counter(const secp256k1_context* ctx, secp256k1_fullagg_secnonce *secnonce,
                                        secp256k1_fullagg_pubnonce *pubnonce, uint64_t nonrepeating_cnt,
                                        const secp256k1_keypair *keypair, const unsigned char *msg32,
                                        const unsigned char *extra_input32) {
    unsigned char buf[32] = { 0 };
    unsigned char seckey[32];
    secp256k1_pubkey pubkey;
    int ret;

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secnonce != NULL);
    ARG_CHECK(keypair != NULL);
    memset(secnonce, 0, sizeof(*secnonce));

    secp256k1_write_be64(buf, nonrepeating_cnt);
    ret = secp256k1_keypair_sec(ctx, seckey, keypair);
    VERIFY_CHECK(ret);
    ret = secp256k1_keypair_pub(ctx, &pubkey, keypair);
    VERIFY_CHECK(ret);
#ifndef VERIFY
    (void) ret;
#endif

    if (!secp256k1_fullagg_nonce_gen_internal(ctx, secnonce, pubnonce, buf, seckey, 
                                              &pubkey, msg32, extra_input32)) {
        return 0;
    }
    secp256k1_memclear_explicit(seckey, sizeof(seckey));
    return 1;
}

static int secp256k1_fullagg_sum_pubnonces(const secp256k1_context* ctx, secp256k1_gej *summed_pubnonces, const secp256k1_fullagg_pubnonce * const* pubnonces, size_t n_pubnonces) {
    size_t i;
    int j;

    secp256k1_gej_set_infinity(&summed_pubnonces[0]);
    secp256k1_gej_set_infinity(&summed_pubnonces[1]);

    for (i = 0; i < n_pubnonces; i++) {
        secp256k1_ge nonce_pts[2];
        if (!secp256k1_fullagg_pubnonce_load(ctx, nonce_pts, pubnonces[i])) {
            return 0;
        }
        for (j = 0; j < 2; j++) {
            secp256k1_gej_add_ge_var(&summed_pubnonces[j], &summed_pubnonces[j], &nonce_pts[j], NULL);
        }
    }
    return 1;
}

/* TODO: Share with MuSig */
/* Aggregate nonces from all signers */
int secp256k1_fullagg_nonce_agg(const secp256k1_context* ctx, secp256k1_fullagg_aggnonce *aggnonce,
                                const secp256k1_fullagg_pubnonce * const* pubnonces, size_t n_pubnonces) {
    secp256k1_gej aggnonce_ptsj[2];
    secp256k1_ge aggnonce_pts[2];

    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(aggnonce != NULL);
    ARG_CHECK(pubnonces != NULL);
    ARG_CHECK(n_pubnonces > 0);

    if (!secp256k1_fullagg_sum_pubnonces(ctx, aggnonce_ptsj, pubnonces, n_pubnonces)) {
        return 0;
    }
    
    secp256k1_ge_set_all_gej_var(aggnonce_pts, aggnonce_ptsj, 2);
    secp256k1_fullagg_aggnonce_save(aggnonce, aggnonce_pts);
    return 1;
}

/* Initializes SHA256 with fixed midstate for "FullAgg/noncecoef" */
static void secp256k1_fullagg_sha256_tagged_noncecoef(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0xe7a1238aul;
    sha->s[1] = 0x8d0cb445ul;
    sha->s[2] = 0x82ea69faul;
    sha->s[3] = 0x6cc8a517ul;
    sha->s[4] = 0xfce019a0ul;
    sha->s[5] = 0xdc36828ful;
    sha->s[6] = 0x727f042bul;
    sha->s[7] = 0xf325ff8eul;
    sha->bytes = 64;
}

/* Compute hash_nonce: H_non(R1 || R2 || X_i || m_i || R2_i for all signers) */
static int secp256k1_fullagg_compute_noncehash(const secp256k1_context* ctx,
                                               unsigned char *noncehash, 
                                               const secp256k1_ge *r1, 
                                               const secp256k1_ge *r2,
                                               const secp256k1_pubkey * const *pubkeys,
                                               const unsigned char * const *messages,
                                               const secp256k1_fullagg_pubnonce * const *pubnonces,
                                               size_t n_signers) {
    unsigned char buf[32];
    size_t i;
    secp256k1_sha256 sha;
    secp256k1_fullagg_sha256_tagged_noncecoef(&sha);
    
    if (secp256k1_ge_is_infinity(r1)) {
        memset(buf, 0, 32);
    } else {
        secp256k1_fe_normalize_var((secp256k1_fe*)&r1->x);
        secp256k1_fe_get_b32(buf, &r1->x);
    }
    secp256k1_sha256_write(&sha, buf, 32);
    
    if (secp256k1_ge_is_infinity(r2)) {
        memset(buf, 0, 32);
    } else {
        secp256k1_fe_normalize_var((secp256k1_fe*)&r2->x);
        secp256k1_fe_get_b32(buf, &r2->x);
    }
    secp256k1_sha256_write(&sha, buf, 32);
    
    /* Write X_i || m_i || R2_i for all signers */
    for (i = 0; i < n_signers; i++) {
        secp256k1_ge pk_ge, nonce_pts[2];
        
        /* Load and write X_i */
        if (!secp256k1_pubkey_load(ctx, &pk_ge, pubkeys[i])) {
            return 0;
        }
        secp256k1_fe_normalize_var(&pk_ge.x);
        secp256k1_fe_get_b32(buf, &pk_ge.x);
        secp256k1_sha256_write(&sha, buf, 32);
        
        /* Write m_i */
        secp256k1_sha256_write(&sha, messages[i], 32);
        
        /* Load and write R2_i */
        if (!secp256k1_fullagg_pubnonce_load(ctx, nonce_pts, pubnonces[i])) {
            return 0;
        }
        if (secp256k1_ge_is_infinity(&nonce_pts[1])) {
            memset(buf, 0, 32);
        } else {
            secp256k1_fe_normalize_var(&nonce_pts[1].x);
            secp256k1_fe_get_b32(buf, &nonce_pts[1].x);
        }
        secp256k1_sha256_write(&sha, buf, 32);
    }
    
    secp256k1_sha256_finalize(&sha, noncehash);
    return 1;
}

/* Initializes SHA256 with fixed midstate for "FullAgg/sig" */
static void secp256k1_fullagg_sha256_tagged_sig(secp256k1_sha256 *sha) {
    secp256k1_sha256_initialize(sha);
    sha->s[0] = 0xd25dfffbul;
    sha->s[1] = 0xd0479fb3ul;
    sha->s[2] = 0x32e0d40eul;
    sha->s[3] = 0x9c4f065aul;
    sha->s[4] = 0xf9bf9e14ul;
    sha->s[5] = 0x8f22cce6ul;
    sha->s[6] = 0x24f00eaeul;
    sha->s[7] = 0xed749b73ul;
    sha->bytes = 64;
}

/* Compute hash_sig: H_sig(L, R, X_i, m_i) where L is list of (X_i, m_i) pairs */
static int secp256k1_fullagg_compute_sighash(const secp256k1_context* ctx,
                                             secp256k1_scalar *c_i, 
                                             const secp256k1_pubkey * const *pubkeys,
                                             const unsigned char * const *messages,
                                             size_t n_signers,
                                             const secp256k1_ge *r, 
                                             size_t signer_index) {
    unsigned char buf[32];
    unsigned char hash[32];
    size_t i;
    secp256k1_ge pk_ge;
    secp256k1_sha256 sha;
    secp256k1_fullagg_sha256_tagged_sig(&sha);
    
    /* Write L (list of all X_i || m_i) */
    for (i = 0; i < n_signers; i++) {
        if (!secp256k1_pubkey_load(ctx, &pk_ge, pubkeys[i])) {
            return 0;
        }
        secp256k1_fe_normalize_var(&pk_ge.x);
        secp256k1_fe_get_b32(buf, &pk_ge.x);
        secp256k1_sha256_write(&sha, buf, 32);
        secp256k1_sha256_write(&sha, messages[i], 32);
    }
    
    /* Write R */
    secp256k1_fe_normalize_var((secp256k1_fe*)&r->x);
    secp256k1_fe_get_b32(buf, &r->x);
    secp256k1_sha256_write(&sha, buf, 32);
    
    /* Write X_i for this signer */
    if (!secp256k1_pubkey_load(ctx, &pk_ge, pubkeys[signer_index])) {
        return 0;
    }
    secp256k1_fe_normalize_var(&pk_ge.x);
    secp256k1_fe_get_b32(buf, &pk_ge.x);
    secp256k1_sha256_write(&sha, buf, 32);
    
    /* Write m_i for this signer */
    secp256k1_sha256_write(&sha, messages[signer_index], 32);
    
    secp256k1_sha256_finalize(&sha, hash);
    secp256k1_scalar_set_b32(c_i, hash, NULL);
    
    return 1;
}

static const unsigned char secp256k1_fullagg_session_magic[4] = { 0xf1, 0x1a, 0x99, 0x04 };

static void secp256k1_fullagg_session_save(secp256k1_fullagg_session *session,
                                           const unsigned char *fin_nonce,
                                           int fin_nonce_parity,
                                           const secp256k1_scalar *noncecoef,
                                           size_t n_signers) {
    unsigned char *ptr = session->data;
    
    memcpy(ptr, secp256k1_fullagg_session_magic, 4);
    ptr += 4;
    memcpy(ptr, fin_nonce, 32);
    ptr += 32;
    *ptr = (unsigned char)fin_nonce_parity;
    ptr += 1;
    secp256k1_scalar_get_b32(ptr, noncecoef);
    ptr += 32;
    secp256k1_write_be64(ptr, (uint64_t)n_signers);
}

static int secp256k1_fullagg_session_load(const secp256k1_context* ctx,
                                          unsigned char *fin_nonce,
                                          int *fin_nonce_parity,
                                          secp256k1_scalar *noncecoef,
                                          size_t *n_signers,
                                          const secp256k1_fullagg_session *session) {
    const unsigned char *ptr = session->data;
    
    ARG_CHECK(secp256k1_memcmp_var(ptr, secp256k1_fullagg_session_magic, 4) == 0);
    ptr += 4;
    memcpy(fin_nonce, ptr, 32);
    ptr += 32;
    *fin_nonce_parity = (int)*ptr;
    ptr += 1;
    secp256k1_scalar_set_b32(noncecoef, ptr, NULL);
    ptr += 32;
    *n_signers = (size_t)secp256k1_read_be64(ptr);
    
    return 1;
}


/* Initialize a FullAgg session */
int secp256k1_fullagg_session_init(const secp256k1_context* ctx, secp256k1_fullagg_session *session,
                                   const secp256k1_fullagg_aggnonce *aggnonce,
                                   const secp256k1_pubkey * const *pubkeys,
                                   const unsigned char * const *messages,
                                   const secp256k1_fullagg_pubnonce * const *pubnonces,
                                   size_t n_signers) {
    secp256k1_ge aggnonce_pts[2];
    secp256k1_ge r;
    secp256k1_gej rj;
    unsigned char noncehash[32];
    unsigned char fin_nonce[32];
    int fin_nonce_parity;
    secp256k1_scalar noncecoef;
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(aggnonce != NULL);
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(messages != NULL);
    ARG_CHECK(pubnonces != NULL);
    ARG_CHECK(n_signers > 0);
    
    if (!secp256k1_fullagg_aggnonce_load(ctx, aggnonce_pts, aggnonce)) {
        return 0;
    }
    
    /* Compute nonce hash b */
    if (!secp256k1_fullagg_compute_noncehash(ctx, noncehash, &aggnonce_pts[0], &aggnonce_pts[1], 
                                             pubkeys, messages, pubnonces, n_signers)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&noncecoef, noncehash, NULL);
    
    /* Compute effective final nonce R = R1 + b*R2 */
    if (secp256k1_ge_is_infinity(&aggnonce_pts[0]) && secp256k1_ge_is_infinity(&aggnonce_pts[1])) {
        /* Both components are infinity, R is infinity */
        secp256k1_ge_set_infinity(&r);
    } else if (secp256k1_ge_is_infinity(&aggnonce_pts[0])) {
        /* Only R1 is infinity, R = b*R2 */
        secp256k1_gej_set_ge(&rj, &aggnonce_pts[1]);
        secp256k1_ecmult(&rj, &rj, &noncecoef, NULL);
        secp256k1_ge_set_gej(&r, &rj);
    } else if (secp256k1_ge_is_infinity(&aggnonce_pts[1])) {
        /* Only R2 is infinity, R = R1 */
        r = aggnonce_pts[0];
    } else {
        /* Normal case: R = R1 + b*R2 */
        secp256k1_gej_set_ge(&rj, &aggnonce_pts[1]);
        secp256k1_ecmult(&rj, &rj, &noncecoef, NULL);
        secp256k1_gej_add_ge_var(&rj, &rj, &aggnonce_pts[0], NULL);
        secp256k1_ge_set_gej(&r, &rj);
    }
    
    /* Store final nonce */
    if (secp256k1_ge_is_infinity(&r)) {
        /* R is infinity - store zeros for x-coordinate */
        memset(fin_nonce, 0, 32);
        fin_nonce_parity = 0;
    } else {
        /* Normal case - normalize and store x-coordinate */
        secp256k1_fe_normalize_var(&r.x);
        secp256k1_fe_normalize_var(&r.y);
        secp256k1_fe_get_b32(fin_nonce, &r.x);
        fin_nonce_parity = secp256k1_fe_is_odd(&r.y);
    }
    
    secp256k1_fullagg_session_save(session, fin_nonce, fin_nonce_parity, &noncecoef, n_signers);
    return 1;
}

/* TODO: Share with MuSig */
static void secp256k1_fullagg_partial_sign_clear(secp256k1_scalar *sk, secp256k1_scalar *k) {
    secp256k1_scalar_clear(sk);
    secp256k1_scalar_clear(&k[0]);
    secp256k1_scalar_clear(&k[1]);
}

/* Create a partial signature */
int secp256k1_fullagg_partial_sign(const secp256k1_context* ctx, secp256k1_fullagg_partial_sig *partial_sig,
                                   secp256k1_fullagg_secnonce *secnonce, const secp256k1_keypair *keypair,
                                   const secp256k1_fullagg_session *session,
                                   const secp256k1_pubkey * const *pubkeys,
                                   const unsigned char * const *messages,
                                   const secp256k1_fullagg_pubnonce * const *pubnonces,
                                   size_t signer_index) {
    secp256k1_scalar sk;
    secp256k1_ge pk, keypair_pk;
    secp256k1_scalar k[2];
    secp256k1_scalar s, c_i;
    unsigned char fin_nonce[32];
    int fin_nonce_parity;
    secp256k1_scalar noncecoef;
    size_t n_signers;
    secp256k1_ge r;
    int ret;
    int is_fin_nonce_zero;
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(secnonce != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(keypair != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(messages != NULL);
    ARG_CHECK(pubnonces != NULL);
    
    /* Load and invalidate secnonce */
    ret = secp256k1_fullagg_secnonce_load(ctx, k, &pk, secnonce);
    /* Always clear the secnonce to avoid nonce reuse */
    memset(secnonce, 0, sizeof(*secnonce));
    if (!ret) {
        secp256k1_fullagg_partial_sign_clear(&sk, k);
        return 0;
    }
    
    if (!secp256k1_keypair_load(ctx, &sk, &keypair_pk, keypair)) {
        secp256k1_fullagg_partial_sign_clear(&sk, k);
        return 0;
    }
    
    /* Verify the keypair matches the secnonce */
    if (!secp256k1_fe_equal(&pk.x, &keypair_pk.x) || !secp256k1_fe_equal(&pk.y, &keypair_pk.y)) {
        secp256k1_fullagg_partial_sign_clear(&sk, k);
        return 0;
    }
    
    if (!secp256k1_fullagg_session_load(ctx, fin_nonce, &fin_nonce_parity, &noncecoef, &n_signers, session)) {
        secp256k1_fullagg_partial_sign_clear(&sk, k);
        return 0;
    }
    
    if (signer_index >= n_signers) {
        secp256k1_fullagg_partial_sign_clear(&sk, k);
        return 0;
    }
    
    /* Verify this signer's pubkey matches */
    {
        secp256k1_ge signer_pk;
        if (!secp256k1_pubkey_load(ctx, &signer_pk, pubkeys[signer_index])) {
            secp256k1_fullagg_partial_sign_clear(&sk, k);
            return 0;
        }
        if (!secp256k1_fe_equal(&pk.x, &signer_pk.x) || !secp256k1_fe_equal(&pk.y, &signer_pk.y)) {
            secp256k1_fullagg_partial_sign_clear(&sk, k);
            return 0;
        }
    }

    /* Verify this signer's R2 appears exactly once at the correct index */
    {
        secp256k1_ge nonce_pts[2];
        secp256k1_gej r2j;
        secp256k1_ge r2_self;
        int found_count = 0;
        int found_index = -1;
        size_t j;
        
        /* Compute our R2 from k[1] */
        secp256k1_ecmult_gen(&ctx->ecmult_gen_ctx, &r2j, &k[1]);
        secp256k1_ge_set_gej(&r2_self, &r2j);
        
        /* Check all pubnonces for our R2 */
        for (j = 0; j < n_signers; j++) {
            if (!secp256k1_fullagg_pubnonce_load(ctx, nonce_pts, pubnonces[j])) {
                secp256k1_fullagg_partial_sign_clear(&sk, k);
                return 0;
            }
            
            /* Check if this R2 matches ours (compare both x and y coordinates) */
            if (!secp256k1_ge_is_infinity(&nonce_pts[1]) && !secp256k1_ge_is_infinity(&r2_self)) {
                if (secp256k1_fe_equal(&r2_self.x, &nonce_pts[1].x) && 
                    secp256k1_fe_equal(&r2_self.y, &nonce_pts[1].y)) {
                    found_count++;
                    found_index = (int)j;
                }
            } else if (secp256k1_ge_is_infinity(&nonce_pts[1]) && secp256k1_ge_is_infinity(&r2_self)) {
                /* Both are infinity */
                found_count++;
                found_index = (int)j;
            }
        }
        
        /* R2 must appear exactly once */
        if (found_count != 1) {
            secp256k1_fullagg_partial_sign_clear(&sk, k);
            return 0;
        }
        
        /* The index where R2 was found must match our signer_index */
        if (found_index != (int)signer_index) {
            secp256k1_fullagg_partial_sign_clear(&sk, k);
            return 0;
        }
    }
    
    /* Check if fin_nonce is zero (infinity case) */
    is_fin_nonce_zero = secp256k1_is_zero_array(fin_nonce, 32);
    
    if (is_fin_nonce_zero) {
        /* R is infinity - cannot sign */
        secp256k1_fullagg_partial_sign_clear(&sk, k);
        return 0;
    }
    
    /* Reconstruct R for computing challenge */
    secp256k1_fe_set_b32_mod(&r.x, fin_nonce);
    if (!secp256k1_ge_set_xo_var(&r, &r.x, fin_nonce_parity)) {
        secp256k1_fullagg_partial_sign_clear(&sk, k);
        return 0;
    }
    
    /* Negate nonces if R has odd y */
    if (fin_nonce_parity) {
        secp256k1_scalar_negate(&k[0], &k[0]);
        secp256k1_scalar_negate(&k[1], &k[1]);
    }
    
    /* Compute signer's challenge c_i */
    if (!secp256k1_fullagg_compute_sighash(ctx, &c_i, pubkeys, messages, n_signers, 
                                           &r, signer_index)) {
        secp256k1_fullagg_partial_sign_clear(&sk, k);
        return 0;
    }
    
    /* Compute s_i = k1_i + b*k2_i + c_i*sk_i */
    secp256k1_scalar_mul(&s, &noncecoef, &k[1]);  /* b*k2_i */
    secp256k1_scalar_add(&s, &s, &k[0]);          /* + k1_i */
    secp256k1_scalar_mul(&k[0], &c_i, &sk);       /* c_i*sk_i (reuse k[0]) */
    secp256k1_scalar_add(&s, &s, &k[0]);          /* + c_i*sk_i */
    
    secp256k1_fullagg_partial_sig_save(partial_sig, &s);
    
    /* Clear sensitive data */
    secp256k1_fullagg_partial_sign_clear(&sk, k);
    secp256k1_scalar_clear(&s);
    secp256k1_scalar_clear(&c_i);
    
    return 1;
}

/* TODO: Share with MuSig */
static void secp256k1_fullagg_effective_nonce(secp256k1_gej *out_nonce, const secp256k1_ge *nonce_pts, const secp256k1_scalar *b) {
    secp256k1_gej tmp;

    secp256k1_gej_set_ge(&tmp, &nonce_pts[1]);
    secp256k1_ecmult(out_nonce, &tmp, b, NULL);
    secp256k1_gej_add_ge_var(out_nonce, out_nonce, &nonce_pts[0], NULL);
}

/* Verify a partial signature */
int secp256k1_fullagg_partial_sig_verify(const secp256k1_context* ctx, const secp256k1_fullagg_partial_sig *partial_sig,
                                         const secp256k1_fullagg_pubnonce *pubnonce, const secp256k1_pubkey *pubkey,
                                         const secp256k1_fullagg_session *session,
                                         const secp256k1_pubkey * const *pubkeys,
                                         const unsigned char * const *messages,
                                         size_t signer_index) {
    unsigned char fin_nonce[32];
    int fin_nonce_parity;
    secp256k1_scalar noncecoef;
    size_t n_signers;
    secp256k1_scalar s, c_i;
    secp256k1_ge pk, r;
    secp256k1_ge nonce_pts[2];
    secp256k1_gej rj, pkj, tmp;
    int result;
    int is_fin_nonce_zero;
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(partial_sig != NULL);
    ARG_CHECK(pubnonce != NULL);
    ARG_CHECK(pubkey != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(messages != NULL);
    
    if (!secp256k1_fullagg_session_load(ctx, fin_nonce, &fin_nonce_parity, &noncecoef, &n_signers, session)) {
        return 0;
    }
    
    if (signer_index >= n_signers) {
        return 0;
    }
    
    if (!secp256k1_fullagg_partial_sig_load(ctx, &s, partial_sig)) {
        return 0;
    }
    
    if (!secp256k1_fullagg_pubnonce_load(ctx, nonce_pts, pubnonce)) {
        return 0;
    }
    
    if (!secp256k1_pubkey_load(ctx, &pk, pubkey)) {
        return 0;
    }

    if (secp256k1_ge_is_infinity(&pk)) {
        return 0;
    }
    
    /* Check if fin_nonce is zero (infinity case) */
    is_fin_nonce_zero = secp256k1_is_zero_array(fin_nonce, 32);
    
    if (is_fin_nonce_zero) {
        return 0;
    }
    
    /* Reconstruct R */
    secp256k1_fe_set_b32_mod(&r.x, fin_nonce);
    if (!secp256k1_ge_set_xo_var(&r, &r.x, fin_nonce_parity)) {
        return 0;
    }
    
    /* Compute effective nonce: R_eff = R1_i + b*R2_i */
    if (secp256k1_ge_is_infinity(&nonce_pts[0]) && secp256k1_ge_is_infinity(&nonce_pts[1])) {
        /* Both nonces are infinity */
        secp256k1_gej_set_infinity(&rj);
    } else if (secp256k1_ge_is_infinity(&nonce_pts[0])) {
        /* Only R1_i is infinity, R_eff = b*R2_i */
        secp256k1_gej_set_ge(&rj, &nonce_pts[1]);
        secp256k1_ecmult(&rj, &rj, &noncecoef, NULL);
    } else if (secp256k1_ge_is_infinity(&nonce_pts[1])) {
        /* Only R2_i is infinity, R_eff = R1_i */
        secp256k1_gej_set_ge(&rj, &nonce_pts[0]);
    } else {
        /* Normal case: R_eff = R1_i + b*R2_i */
        secp256k1_fullagg_effective_nonce(&rj, nonce_pts, &noncecoef);
    }
    
    /* Negate if R has odd y */
    if (fin_nonce_parity) {
        secp256k1_gej_neg(&rj, &rj);
    }
    
    /* Compute signer's challenge c_i */
    if (!secp256k1_fullagg_compute_sighash(ctx, &c_i, pubkeys, messages, n_signers, 
                                           &r, signer_index)) {
        return 0;
    }
    
    /* Verify: s_i*G = R_eff + c_i*pk_i */
    secp256k1_scalar_negate(&s, &s);
    secp256k1_gej_set_ge(&pkj, &pk);
    secp256k1_ecmult(&tmp, &pkj, &c_i, &s);
    secp256k1_gej_add_var(&tmp, &tmp, &rj, NULL);
    
    result = secp256k1_gej_is_infinity(&tmp);
    
    return result;
}

/* Aggregate partial signatures */
int secp256k1_fullagg_partial_sig_agg(const secp256k1_context* ctx, unsigned char *sig64,
                                      const secp256k1_fullagg_session *session,
                                      const secp256k1_fullagg_partial_sig * const *partial_sigs,
                                      size_t n_sigs) {
    unsigned char fin_nonce[32];
    int fin_nonce_parity;
    secp256k1_scalar noncecoef;
    size_t n_signers;
    secp256k1_scalar s_agg;
    size_t i;
    int is_fin_nonce_zero;
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(session != NULL);
    ARG_CHECK(partial_sigs != NULL);
    ARG_CHECK(n_sigs > 0);
    
    if (!secp256k1_fullagg_session_load(ctx, fin_nonce, &fin_nonce_parity, &noncecoef, &n_signers, session)) {
        return 0;
    }
    
    ARG_CHECK(n_sigs == n_signers);
    
    /* Check if fin_nonce (R) is zero (infinity case) */
    is_fin_nonce_zero = secp256k1_is_zero_array(fin_nonce, 32);
    
    if (is_fin_nonce_zero) {
        return 0;
    }
    
    /* Aggregate all the s values */
    secp256k1_scalar_set_int(&s_agg, 0);
    for (i = 0; i < n_sigs; i++) {
        secp256k1_scalar s_i;
        if (!secp256k1_fullagg_partial_sig_load(ctx, &s_i, partial_sigs[i])) {
            return 0;
        }
        secp256k1_scalar_add(&s_agg, &s_agg, &s_i);
    }
    
    /* Output aggregate signature */
    memcpy(sig64, fin_nonce, 32);
    secp256k1_scalar_get_b32(&sig64[32], &s_agg);
    
    return 1;
}

/* Verify a FullAgg aggregate signature */
int secp256k1_fullagg_verify(const secp256k1_context* ctx, const unsigned char *sig64,
                             const secp256k1_pubkey * const *pubkeys,
                             const unsigned char * const *messages,
                             size_t n_signers) {
    secp256k1_scalar s;
    secp256k1_ge r;
    secp256k1_gej c_sum_pk;
    secp256k1_gej tmp;
    size_t i;
    int overflow;
    
    VERIFY_CHECK(ctx != NULL);
    ARG_CHECK(sig64 != NULL);
    ARG_CHECK(pubkeys != NULL);
    ARG_CHECK(messages != NULL);
    ARG_CHECK(n_signers > 0);
    
    /* Parse signature */
    if (!secp256k1_fe_set_b32_limit(&r.x, sig64)) {
        return 0;
    }
    secp256k1_scalar_set_b32(&s, &sig64[32], &overflow);
    if (overflow) {
        return 0;
    }
    
    /* Check even y */
    if (!secp256k1_ge_set_xo_var(&r, &r.x, 0)) {
        return 0;
    }

    /* Compute sum of c_i*pk_i */
    secp256k1_gej_set_infinity(&c_sum_pk);
    for (i = 0; i < n_signers; i++) {
        secp256k1_scalar c_i;
        secp256k1_gej pkj;
        secp256k1_ge pk_ge;
        
        if (!secp256k1_pubkey_load(ctx, &pk_ge, pubkeys[i])) {
            return 0;
        }

        /* Check that no public key is the identity element */
        if (secp256k1_ge_is_infinity(&pk_ge)) {
            return 0;
        }
        
        if (!secp256k1_fullagg_compute_sighash(ctx, &c_i, pubkeys, messages, n_signers, &r, i)) {
            return 0;
        }
        secp256k1_gej_set_ge(&pkj, &pk_ge);
        secp256k1_ecmult(&tmp, &pkj, &c_i, NULL);
        secp256k1_gej_add_var(&c_sum_pk, &c_sum_pk, &tmp, NULL);
    }
    
    /* Verify: s*G = R + sum(c_i*pk_i) */
    secp256k1_scalar_negate(&s, &s);
    secp256k1_ecmult(&tmp, &c_sum_pk, &secp256k1_scalar_one, &s);
    secp256k1_gej_add_ge_var(&tmp, &tmp, &r, NULL);
    
    return secp256k1_gej_is_infinity(&tmp);
}

#endif /* SECP256K1_MODULE_SCHNORRSIG_FULLAGG_MAIN_H */
