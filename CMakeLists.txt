cmake_minimum_required(VERSION 3.12)

project(libsecp256k1 VERSION 0.1 LANGUAGES C)
set(CMAKE_C_STANDARD 90)
set(CMAKE_C_STANDARD_REQUIRED ON)

if (CMAKE_C_FLAGS STREQUAL "")
  set(CMAKE_C_FLAGS "-g")
endif()

if (CMAKE_CROSSCOMPILING)
  message(FATAL_ERROR "Currently Cmake makefile doesn't support cross compiling.")
endif()

if (APPLE AND NOT BIGNUM_NO)
  find_program("brew" brew)
  if (NOT brew STREQUAL "")
    # These Homebrew packages may be keg-only, meaning that they won't be found
    # in expected paths because they may conflict with system files. Ask
    # Homebrew where each one is located, then adjust paths accordingly.
    execute_process(COMMAND ${brew} --prefix openssl OUTPUT_VARIABLE openssl_prefix OUTPUT_STRIP_TRAILING_WHITESPACE)
    execute_process(COMMAND ${brew} --prefix gmp OUTPUT_VARIABLE gmp_prefix OUTPUT_STRIP_TRAILING_WHITESPACE)
    if (NOT openssl_prefix STREQUAL "")
      set(ENV{PKG_CONFIG_PATH} "${openssl_prefix}/lib/pkgconfig:$PKG_CONFIG_PATH")
    endif()
    if (NOT gmp_prefix STREQUAL "")
      set(ENV{PKG_CONFIG_PATH} "${gmp_prefix}/lib/pkgconfig:$PKG_CONFIG_PATH")
      set(GMP_C_FLAGS "-I${gmp_prefix}/include")
      set(GMP_LIBS "-L${gmp_prefix}/lib -lgmp")
    endif()
  else()
    find_program("port" port)
    # if homebrew isn't installed and macports is, add the macports default paths
    # as a last resort.
    if (NOT port STREQUAL "")
      set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -isystem /opt/local/include")
      set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} -L/opt/local/lib")
    endif()
  endif()
endif()

include(CheckCCompilerFlag)

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -W")
set(WARN_C_FLAGS "-std=c89 -pedantic -Wall -Wextra -Wcast-align -Wnested-externs -Wshadow -Wstrict-prototypes -Wno-unused-function -Wno-long-long -Wno-overlength-strings")
set(SAVED_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${WARN_C_FLAGS}")
check_c_compiler_flag(${CMAKE_C_FLAGS} USE_WARN_CFLAGS)
if (NOT USE_WARN_CFLAGS)
  set(CMAKE_C_FLAGS "${SAVED_C_FLAGS}")
endif()

set(SAVED_C_FLAGS "${CMAKE_C_FLAGS}")
set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -fvisibility=hidden")
check_c_compiler_flag(${CMAKE_C_FLAGS} USE_OPAQUE_CFLAGS)
if (NOT USE_OPAQUE_CFLAGS)
  set(CMAKE_C_FLAGS "${SAVED_C_FLAGS}")
endif()

option(BENCHMARK "compile benchmark (default is on)" ON)
option(COVERAGE "enable compiler flags to support kcov coverage analysis" OFF)
option(TESTS "compile tests (default is on)" ON)
option(OPENSSL_TESTS "enable OpenSSL tests, if OpenSSL is available (default is auto)" OFF)
option(EXPERIMENTAL "allow experimental configure options (default is off)" OFF)
option(EXHAUSTIVE_TESTS "compile exhaustive tests (default is on)" ON)
option(ENDOMORPHISM "enable endomorphism (default is off)" OFF)
option(ECMULT_STATIC_PRECOMPUTATION "enable precomputed ecmult table for signing (default is on)" ON)
option(MODULE_ECDH "enable ECDH shared secret computation (experimental)" OFF)
option(MODULE_RECOVERY "enable ECDSA pubkey recovery module (default is off)" OFF)
option(JNI "enable libsecp256k1_jni (default is off)" OFF)

option(FIELD_64BIT "enable 64 bit field implementation (default is auto)" OFF)
option(FIELD_32BIT "enable 32 bit field implementation (default is auto)" OFF)

option(BIGNUM_GMP "enable GMP bignum implementation (default is auto)" OFF)
option(BIGNUM_NO "don't use any bignum implementation (default is auto)" OFF)

option(SCALAR_64BIT "enable 64 bit scalar implementation (default is auto)" OFF)
option(SCALAR_32BIT "enable 32 bit scalar implementation (default is auto)" OFF)

option(ASM_x86_64 "enable x86_64 assembly optimization (default is auto)" OFF)
option(ASM_ARM "enable ARM assembly optimization (default is auto)" OFF)
option(ASM_NO "don't use any assembly optimization (default is auto)" OFF)

include(CheckTypeSize)
check_type_size("__int128" INT128)
if (NOT INT128 STREQUAL "")
  set(INT128 ON)
else()
  set(INT128 OFF)
endif()

include(CheckCSourceCompiles)
check_c_source_compiles("int main() {__builtin_expect(0,0);return 0;}" BUILTIN_EXPECT)

if (COVERAGE)
  # Define this symbol to compile out all VERIFY code
  add_compile_definitions(COVERAGE=1)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O0 --coverage")
  set(CMAKE_MODULE_LINKER_FLAGS "${CMAKE_MODULE_LINKER_FLAGS} --coverage")
  set(CMAKE_STATIC_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} --coverage")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} --coverage")
else()
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -O3")
endif()

set(PRECOMP ${ECMULT_STATIC_PRECOMPUTATION})

if (NOT ASM_ARM)
  check_c_source_compiles("\
  #include <stdint.h> \n\
  uint64_t a = 11, tmp; \n\
  int main(void) {__asm__ __volatile__(\"movq 0x100000000,%1; mulq %%rsi\" : \"+a\"(a) : \"S\"(tmp) : \"cc\", \"%rdx\");return 0;}" ASM_64BIT)
  if (ASM_64BIT)
    set(ASM_x86_64 ON)
  elseif(ASM_x86_64)
    message(FATAL_ERROR "x86_64 assembly optimization requested but not available.")
  # else ASM_NO
  endif()
endif()

# Assumes the user didn't choose both
if (NOT FIELD_32BIT)
  if (ASM_x86_64 OR INT128)
    set(FIELD_64BIT ON)
  elseif(FIELD_64BIT)
    message(FATAL_ERROR "64bit field explicitly requested but neither __int128 support or x86_64 assembly available.")
  endif()
endif()

# Assumes the user didn't choose both
if (NOT SCALAR_32BIT)
  if (INT128)
    set(SCALAR_64BIT ON)
  elseif(SCALAR_64BIT)
    message(FATAL_ERROR "64bit scalar explicitly requested but __int128 support not available.")
  # else use SCALAR_32BIT
  endif()
endif()

if (NOT BIGNUM_NO)
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GMP_C_FLAGS} ${GMP_LIBS}")
  set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_SHARED_LINKER_FLAGS} ${GMP_LIBS}")
  # No need to append CMAKE_C_FLAGS to CMAKE_REQUIRED_FLAGS
  check_c_source_compiles("\
  #include <gmp.h>\n\
  mpz_t integ; int main() {return 0;}" GMP)
  if (GMP)
    # Define this symbol if libgmp is installed
    add_compile_definitions(HAVE_LIBGMP=1)
    set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} ${GMP_C_FLAGS} ${GMP_LIBS}")
    set(BIGNUM_GMP ON)
  elseif(BIGNUM_GMP)
      message(FATAL_ERROR "gmp bignum explicitly requested but libgmp not available.")
  # else BIGNUM_NO
  endif()
endif()

set(CMAKE_REQUIRED_FLAGS "")

set(USE_EXTERNAL_ASM OFF)
if (ASM_x86_64)
  # Define this symbol to enable x86_64 assembly optimizations
  add_compile_definitions(USE_ASM_X86_64=1)
else()
  if(ASM_ARM)
    set(USE_EXTERNAL_ASM ON)
  endif()
  # no asm
endif()

if(BUILTIN_EXPECT)
  add_compile_definitions(HAVE_BUILTIN_EXPECT)
endif()

if ((TESTS OR EXHAUSTIVE_TESTS) AND NOT COVERAGE)
  add_compile_definitions(VERIFY)
endif()

if (FIELD_64BIT)
  # Define this symbol to use the FIELD_5X52 implementation
  add_compile_definitions(USE_FIELD_5X52=1)
else()
  # Define this symbol to use the FIELD_10X26 implementation
  add_compile_definitions(USE_FIELD_10X26=1)
endif()

if (BIGNUM_GMP)
  # Define this symbol if libgmp is installed
  add_compile_definitions(HAVE_LIBGMP=1)
  # Define this symbol to use the gmp implementation for num
  add_compile_definitions(USE_NUM_GMP=1)
  # Define this symbol to use the num-based field inverse implementation
  add_compile_definitions(USE_FIELD_INV_NUM=1)
  # Define this symbol to use the num-based scalar inverse implementation
  add_compile_definitions(USE_SCALAR_INV_NUM=1)
else()
  # Define this symbol to use no num implementation
  add_compile_definitions(USE_NUM_NONE=1)
  # Define this symbol to use the native field inverse implementation
  add_compile_definitions(USE_FIELD_INV_BUILTIN=1)
  # Define this symbol to use the native scalar inverse implementation
  add_compile_definitions(USE_SCALAR_INV_BUILTIN=1)
endif()

if (SCALAR_64BIT)
  # Define this symbol to use the 4x64 scalar implementation
  add_compile_definitions(USE_SCALAR_4X64=1)
else()
  # Define this symbol to use the 8x32 scalar implementation
  add_compile_definitions(USE_SCALAR_8X32=1)
endif()

if (TESTS)
  # TODO: here add OpenSSL tests
  if (MINGW)
  endif()
else()
  if (OPENSSL_TESTS)
    message(FATAL_ERROR "OpenSSL tests requested but tests are not enabled.")
  endif()
endif()

if (JNI)
  # TODO: add jni
endif()

if (ENDOMORPHISM)
  # Define this symbol to use endomorphism optimization
  add_compile_definitions(USE_ENDOMORPHISM=1)
endif()

if (PRECOMP)
  # Define this symbol to use a statically generated ecmult table
  add_compile_definitions(USE_ECMULT_STATIC_PRECOMPUTATION=1)
endif()

if (MODULE_ECDH)
  # Define this symbol to enable the ECDH module
  add_compile_definitions(ENABLE_MODULE_ECDH=1)
endif()

if (MODULE_RECOVERY)
  # Define this symbol to enable the ECDSA pubkey recovery module
  add_compile_definitions(ENABLE_MODULE_RECOVERY=1)
endif()

if (USE_EXTERNAL_ASM)
  # Define this symbol if an external (non-inline) assembly implementation is used
  add_compile_definitions(USE_EXTERNAL_ASM=1)
endif()

if (INT128)
  add_compile_definitions(HAVE___INT128=1)
endif()

add_compile_definitions(SECP256K1_BUILD)

message("Using static precomputation: ${PRECOMP}")
message("Using x86_64 ASM: ${ASM_x86_64}")
message("Using ARM ASM: ${ASM_ARM}")
message("Using external ASM: ${USE_EXTERNAL_ASM}")
message("Using 64 bit field implementation: ${FIELD_64BIT}")
message("Using GMP bignum implementation: ${BIGNUM_GMP}")
message("Using 64 bit scalar implementation: ${SCALAR_64BIT}")
message("Using endomorphism optimizations: ${ENDOMORPHISM}")
message("Building benchmarks: ${BENCHMARK}")
message("Building for coverage analysis: ${COVERAGE}")
message("Building ECDH module: ${MODULE_ECDH}")
message("Building ECDSA pubkey recovery module: ${MODULE_RECOVERY}")
message("Using JNI: ${JNI}")

if (EXPERIMENTAL)
  message("******")
  message("WARNING: experimental build")
  message("Experimental features do not have stable APIs or properties, and may not be safe for production use.")
  message("Building ECDH module: ${MODULE_ECDH}.")
  message("******")
else()
  if (MODULE_ECDH)
    message(FATAL_ERROR "ECDH module is experimental. Use -DEXPERIMENTAL to allow.")
  endif()
  if (ASM_ARM)
    message(FATAL_ERROR "ARM assembly optimization is experimental. Use -DEXPERIMENTAL to allow.")
  endif()
endif()

# Use -DBUILD_SHARED_LIBS=ON to generate SHARED library

set(CMAKE_RUNTIME_OUTPUT_DIRECTORY ${PROJECT_SOURCE_DIR})

add_subdirectory(src)

set_target_properties(secp256k1 PROPERTIES PUBLIC_HEADER include/secp256k1.h)
set_target_properties(secp256k1 PROPERTIES OUTPUT_NAME secp256k1)
