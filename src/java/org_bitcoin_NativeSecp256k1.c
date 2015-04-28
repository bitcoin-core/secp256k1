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
