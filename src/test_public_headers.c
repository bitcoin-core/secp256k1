/* Test file to ensure public headers compile as C89 independently */
#include "secp256k1.h"
#include "secp256k1_preallocated.h"

#ifdef ENABLE_MODULE_ECDH
# include "secp256k1_ecdh.h"
#endif

#ifdef ENABLE_MODULE_ELLSWIFT
# include "secp256k1_ellswift.h"
#endif

#ifdef ENABLE_MODULE_EXTRAKEYS
# include "secp256k1_extrakeys.h"
#endif

#ifdef ENABLE_MODULE_MUSIG
# include "secp256k1_musig.h"
#endif

#ifdef ENABLE_MODULE_RECOVERY
# include "secp256k1_recovery.h"
#endif

#ifdef ENABLE_MODULE_SCHNORRSIG
# include "secp256k1_schnorrsig.h"
#endif

int main(void) {
    /* If this program compiles, the public headers are at least syntactically valid */
    return 0;
}
