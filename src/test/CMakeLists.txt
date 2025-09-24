# OBJECT library, because were are not interested in linking this.
# EXCLUDE_FROM_ALL, because it is explicitly built as a test.
add_library(secp256k1_build_public_headers OBJECT EXCLUDE_FROM_ALL
  secp256k1.c
  secp256k1_ecdh.c
  secp256k1_ellswift.c
  secp256k1_extrakeys.c
  secp256k1_musig.c
  secp256k1_preallocated.c
  secp256k1_recovery.c
  secp256k1_schnorrsig.c
)

add_test(NAME secp256k1_build_public_headers COMMAND ${CMAKE_COMMAND}
  --build ${CMAKE_BINARY_DIR}
  --target secp256k1_build_public_headers
  --config $<CONFIG>
)
