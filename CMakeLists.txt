cmake_minimum_required(VERSION 3.2)

project(secp256k1 LANGUAGES C)


add_library(secp256k1 SHARED ${SOURCES} src/secp256k1.c)
target_include_directories(secp256k1 PUBLIC . ./src PRIVATE ${GMP_INCLUDE_DIR})
target_compile_definitions(secp256k1
	PUBLIC -DUSE_NUM_NONE=1 -DUSE_FIELD_5X52=1 -DUSE_FIELD_INV_BUILTIN=1 -DUSE_SCALAR_4X64=1 -DUSE_SCALAR_INV_BUILTIN=1 -DHAVE___INT128=1 -DVERIFY=1
	PRIVATE -DENABLE_MODULE_ECDH -DENABLE_MODULE_RECOVERY -DENABLE_MODULE_SCHNORR
)

add_executable(tests src/tests.c)
target_link_libraries(tests secp256k1)

add_executable(bench_ecdh src/bench_ecdh.c)
target_link_libraries(bench_ecdh secp256k1)

add_executable(bench_internal src/bench_internal.c)
target_link_libraries(bench_internal secp256k1)

add_executable(bench_recover src/bench_recover.c)
target_link_libraries(bench_recover secp256k1)

add_executable(bench_schnorr_verify src/bench_schnorr_verify.c)
target_link_libraries(bench_schnorr_verify secp256k1)

add_executable(bench_sign src/bench_sign.c)
target_link_libraries(bench_sign secp256k1)

add_executable(bench_verify src/bench_verify.c)
target_link_libraries(bench_verify secp256k1)
