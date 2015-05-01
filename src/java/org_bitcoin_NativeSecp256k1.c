#include "org_bitcoin_NativeSecp256k1.h"
#include "include/secp256k1.h"

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject)
{
	secp256k1_context_t *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
	int sigLen = *((int*)(data + 32));
	int pubLen = *((int*)(data + 32 + 4));

	(void)classObject;

	return secp256k1_ecdsa_verify(vrfy, data, data+32+8, sigLen, data+32+8+sigLen, pubLen);
}

JNIEXPORT jbyteArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ecdsa_1sign
  (JNIEnv* env, jclass classObject, jobject byteBufferObject)
{
	secp256k1_context_t *sgn = secp256k1_context_create(SECP256K1_CONTEXT_SIGN);
	unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
	unsigned char* secKey = (unsigned char*) (data + 32);

  jbyteArray sigArray;

  unsigned char sig[72];
  int siglen = 72;

  int ret = secp256k1_ecdsa_sign(sgn, data, sig, &siglen, secKey, NULL, NULL );

  sigArray = (*env)->NewByteArray(env, siglen);
  (*env)->SetByteArrayRegion(env, sigArray, 0, siglen, (jbyte*)sig);

	(void)classObject; (void)ret;
	return sigArray;
}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1seckey_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject)
{
	secp256k1_context_t *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);

	(void)classObject;

	return secp256k1_ec_seckey_verify(vrfy, secKey);
}

JNIEXPORT jint JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1verify
  (JNIEnv* env, jclass classObject, jobject byteBufferObject)
{
	secp256k1_context_t *vrfy = secp256k1_context_create(SECP256K1_CONTEXT_VERIFY);
	unsigned char* data = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
	int pubLen = *((int*)(data));
	unsigned char* pubKey = (unsigned char*) (data + 4);

	(void)classObject;

	return secp256k1_ec_pubkey_verify(vrfy, pubKey, pubLen);
}

JNIEXPORT jbyteArray JNICALL Java_org_bitcoin_NativeSecp256k1_secp256k1_1ec_1pubkey_1create
  (JNIEnv* env, jclass classObject, jobject byteBufferObject)
{
	secp256k1_context_t *sgnvrfy = secp256k1_context_create(SECP256K1_CONTEXT_SIGN | SECP256K1_CONTEXT_VERIFY);
	unsigned char* secKey = (unsigned char*) (*env)->GetDirectBufferAddress(env, byteBufferObject);
	int compressed = *((int*)(secKey + 32));

  unsigned char pubkey[65];
  int pubkeyLen = 65;

  jbyteArray pubkeyArray;

  int ret = secp256k1_ec_pubkey_create(sgnvrfy, pubkey, &pubkeyLen, secKey, compressed );

  pubkeyArray = (*env)->NewByteArray(env, pubkeyLen);
  (*env)->SetByteArrayRegion(env, pubkeyArray, 0, pubkeyLen, (jbyte*)pubkey);

	(void)classObject; (void)ret;
	return pubkeyArray;
}
