include_directories(${PROJECT_SOURCE_DIR})
include_directories("${PROJECT_SOURCE_DIR}/include")

add_library(secp256k1 secp256k1.c)
if (TESTS)
  add_executable(test tests.c)
endif()
if (EXHAUSTIVE_TESTS)
  add_executable(exhaustive_test tests_exhaustive.c)
endif()

if (NOT COVERAGE)
  if (TESTS)
    target_compile_definitions(test PRIVATE VERIFY)
  endif()
  if (EXHAUSTIVE_TESTS)
    target_compile_definitions(exhaustive_test PRIVATE VERIFY)
  endif()
endif()

if (ECMULT_STATIC_PRECOMPUTATION)
  add_executable(precomputation gen_context.c)
  # alternatives considered:
  # add_file_dependencies, add_dependencies, add_custom_command
  add_custom_target(precomputed_table
    COMMAND "${PROJECT_SOURCE_DIR}/precomputation"
    BYPRODUCTS "${PROJECT_SOURCE_DIR}/src/ecmult_static_context.h"
    DEPENDS precomputation
    WORKING_DIRECTORY ${PROJECT_SOURCE_DIR}
  )
  add_dependencies(secp256k1 precomputed_table)
  if (TESTS)
    add_dependencies(test precomputed_table)
  endif()
  if (EXHAUSTIVE_TESTS)
    add_dependencies(exhaustive_test precomputed_table)
  endif()
endif()
