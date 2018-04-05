include(CheckTypeSize)

add_library(
    secp256k1
    secp256k1.c
)

target_include_directories(secp256k1 PRIVATE ${PROJECT_SOURCE_DIR})

check_type_size(__int128 have_int128 BUILTIN_TYPES_ONLY)
if(have_int128)
    target_compile_definitions(secp256k1 PRIVATE HAVE___INT128 USE_SCALAR_4X64)
else()
    target_compile_definitions(secp256k1 PRIVATE USE_SCALAR_8X32)
endif()


if(SECP256K1_USE_GMP)
    target_compile_definitions(secp256k1 PRIVATE USE_NUM_GMP USE_FIELD_INV_NUM USE_SCALAR_INV_NUM)
else()
    target_compile_definitions(secp256k1 PRIVATE USE_NUM_NONE USE_FIELD_INV_BUILTIN USE_SCALAR_INV_BUILTIN)
endif()

if(SECP256K1_USE_FIELD_5X52)
    target_compile_definitions(secp256k1 PRIVATE USE_FIELD_5X52)
else()
    target_compile_definitions(secp256k1 PRIVATE USE_FIELD_10X26)
endif()
