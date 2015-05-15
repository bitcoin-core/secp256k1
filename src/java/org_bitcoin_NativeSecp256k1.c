#include <stdlib.h>
#include "org_bitcoin_NativeSecp256k1.h"
#include "include/secp256k1.h"

JNIEXPORT jlong JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1init_1context
  (JNIEnv* env, jclass classObject)
{
  secp256k1_context_t *ctx = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);

  (void)classObject;(void)env;

  return (jlong)ctx;
}

JNIEXPORT jlong JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ctx_1clone
  (JNIEnv* env, jclass classObject, jlong ctx_l)
{
  const secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  jlong ctx_clone_l = (jlong) secp256k1_context_clone(ctx);

  (void)classObject;(void)env;

  return (jlong)ctx_clone_l;

}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1context_1randomize
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  const unsigned char* seed = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  (void)classObject;

  return secp256k1_context_randomize(ctx, seed);

}

JNIEXPORT void JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1destroy_1context
  (JNIEnv* env, jclass classObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  secp256k1_context_destroy(ctx);

  (void)classObject;(void)env;
}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint sigLen, jint pubLen)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  (void)classObject;

  return secp256k1_ecdsa_verify(ctx, data, data+32, sigLen, data+32+sigLen, pubLen);
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  unsigned char* secKey = (unsigned char*) (data + 32);

  jobjectArray retArray;
  jbyteArray sigArray, intsByteArray;
  unsigned char intsarray[2];

  unsigned char sig[72];
  int siglen = 72;

  int ret = secp256k1_ecdsa_sign(ctx, data, sig, &siglen, secKey, NULL, NULL );

  intsarray[0] = siglen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  sigArray = (*env)->NewByteArray(env, siglen);
  (*env)->SetByteArrayRegion(env, sigArray, 0, siglen, (jbyte*)sig);
  (*env)->SetObjectArrayElement(env, retArray, 0, sigArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1seckey_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  (void)classObject;

  return secp256k1_ec_seckey_verify(ctx, secKey);
}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint pubLen)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* pubKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  (void)classObject;

  return secp256k1_ec_pubkey_verify(ctx, pubKey, pubLen);
}

JNIEXPORT jbyteArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1create
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint compressed)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  unsigned char pubkey[65];
  int pubkeyLen = 65;

  jobjectArray retArray;
  jbyteArray pubkeyArray, intsByteArray;
  unsigned char intsarray[2];

  int ret = secp256k1_ec_pubkey_create(ctx, pubkey, &pubkeyLen, secKey, compressed );

  intsarray[0] = pubkeyLen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  pubkeyArray = (*env)->NewByteArray(env, pubkeyLen);
  (*env)->SetByteArrayRegion(env, pubkeyArray, 0, pubkeyLen, (jbyte*)pubkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, pubkeyArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;

}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1decompress
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint pubLen)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  unsigned char* pubkey = (unsigned char*) malloc(sizeof(unsigned char)*65);

  unsigned char* temp = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  int i, ret;
  jobjectArray retArray;
  jbyteArray pubkeyArray, intsByteArray;
  unsigned char intsarray[2];

  for(i = 0; i < pubLen; i++) pubkey[i] = temp[i];

  ret = secp256k1_ec_pubkey_decompress(ctx, pubkey, &pubLen);

  intsarray[0] = pubLen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  pubkeyArray = (*env)->NewByteArray(env, pubLen);
  (*env)->SetByteArrayRegion(env, pubkeyArray, 0, pubLen, (jbyte*)pubkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, pubkeyArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}


JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1privkey_1export
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint privLen, jint compressed)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  const unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  int i, ret;
  jobjectArray retArray;
  jbyteArray privkeyArray, intsByteArray;
  unsigned char intsarray[2];

  unsigned char* privkey = (unsigned char*) malloc(sizeof(unsigned char)*279);

  for(i = 0; i < privLen; i++) privkey[i] = secKey[i];

  ret = secp256k1_ec_privkey_export(ctx, secKey, privkey ,&privLen, compressed);

  intsarray[0] = privLen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  privkeyArray = (*env)->NewByteArray(env, privLen);
  (*env)->SetByteArrayRegion(env, privkeyArray, 0, privLen, (jbyte*)privkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, privkeyArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1privkey_1import
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint privLen)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;

  const unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

  jobjectArray retArray;
  jbyteArray privkeyArray, intsByteArray;
  unsigned char intsarray[2];

  unsigned char privkey[32];

  int ret = secp256k1_ec_privkey_import(ctx, privkey, secKey, privLen);

  privLen = 32;

  intsarray[0] = privLen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  privkeyArray = (*env)->NewByteArray(env, privLen);
  (*env)->SetByteArrayRegion(env, privkeyArray, 0, privLen, (jbyte*)privkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, privkeyArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}


JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign_1compact
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  const unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* secKey = (unsigned char*) (data + 32);

  jobjectArray retArray;
  jbyteArray sigArray, intsByteArray;
  unsigned char intsarray[2];

  unsigned char sig[64];
  int siglen = 64;
  int recID;

  int ret = secp256k1_ecdsa_sign_compact(ctx, data, sig, secKey, NULL, NULL, &recID );

  intsarray[0] = recID;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  sigArray = (*env)->NewByteArray(env, siglen);
  (*env)->SetByteArrayRegion(env, sigArray, 0, siglen, (jbyte*)sig);
  (*env)->SetObjectArrayElement(env, retArray, 0, sigArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}


JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1recover_1compact
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint compressed, jint recid)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  const unsigned char* msg = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* sig = (unsigned char*) (msg + 32);

  jobjectArray retArray;
  jbyteArray pubArray, intsByteArray;
  unsigned char intsarray[2];

  unsigned char pubkey[64];
  int pubkeylen;

  int ret = secp256k1_ecdsa_recover_compact(ctx, msg, sig, pubkey, &pubkeylen, compressed, recid );

  intsarray[0] = pubkeylen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  pubArray = (*env)->NewByteArray(env, pubkeylen);
  (*env)->SetByteArrayRegion(env, pubArray, 0, pubkeylen, (jbyte*)pubkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, pubArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1privkey_1tweak_1add
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* privkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* tweak = (unsigned char*) (privkey + 32);

  jobjectArray retArray;
  jbyteArray privArray, intsByteArray;
  unsigned char intsarray[2];

  int privkeylen = 32;

  int ret = secp256k1_ec_privkey_tweak_add(ctx, privkey, tweak);

  intsarray[0] = privkeylen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  privArray = (*env)->NewByteArray(env, privkeylen);
  (*env)->SetByteArrayRegion(env, privArray, 0, privkeylen, (jbyte*)privkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, privArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1privkey_1tweak_1mul
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* privkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* tweak = (unsigned char*) (privkey + 32);

  jobjectArray retArray;
  jbyteArray privArray, intsByteArray;
  unsigned char intsarray[2];

  int privkeylen = 32;

  int ret = secp256k1_ec_privkey_tweak_mul(ctx, privkey, tweak);

  intsarray[0] = privkeylen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  privArray = (*env)->NewByteArray(env, privkeylen);
  (*env)->SetByteArrayRegion(env, privArray, 0, privkeylen, (jbyte*)privkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, privArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1pubkey_1tweak_1add
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* pubkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* tweak = (unsigned char*) (pubkey + publen);

  jobjectArray retArray;
  jbyteArray pubArray, intsByteArray;
  unsigned char intsarray[2];

  int ret = secp256k1_ec_pubkey_tweak_add(ctx, pubkey, publen, tweak);

  intsarray[0] = publen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  pubArray = (*env)->NewByteArray(env, publen);
  (*env)->SetByteArrayRegion(env, pubArray, 0, publen, (jbyte*)pubkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, pubArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}

JNIEXPORT jobjectArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1pubkey_1tweak_1mul
  (JNIEnv* env, jclass classObject, jobject byteBufferObject, jlong ctx_l, jint publen)
{
  secp256k1_context_t *ctx = (secp256k1_context_t*)ctx_l;
  unsigned char* pubkey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
  const unsigned char* tweak = (unsigned char*) (pubkey + publen);

  jobjectArray retArray;
  jbyteArray pubArray, intsByteArray;
  unsigned char intsarray[2];

  int ret = secp256k1_ec_pubkey_tweak_mul(ctx, pubkey, publen, tweak);

  intsarray[0] = publen;
  intsarray[1] = ret;

  retArray = (*env)->NewObjectArray(env, 2,
    (*env)->FindClass(env, "[B"),
    (*env)->NewByteArray(env, 1));

  pubArray = (*env)->NewByteArray(env, publen);
  (*env)->SetByteArrayRegion(env, pubArray, 0, publen, (jbyte*)pubkey);
  (*env)->SetObjectArrayElement(env, retArray, 0, pubArray);

  intsByteArray = (*env)->NewByteArray(env, 2);
  (*env)->SetByteArrayRegion(env, intsByteArray, 0, 2, (jbyte*)intsarray);
  (*env)->SetObjectArrayElement(env, retArray, 1, intsByteArray);

  (void)classObject;

  return retArray;
}
