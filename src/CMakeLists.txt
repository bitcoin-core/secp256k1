include_directories(${PROJECT_SOURCE_DIR})

add_library(secp256k1 secp256k1.c)
if (TESTS)
    add_executable(test tests.c)
endif()
if (EXHAUSTIVE_TESTS)
    add_executable(exhaustive_test tests_exhaustive.c)
endif()

if (PRECOMP)
    add_executable(precomputation gen_context.c)
    set_target_properties(precomputation PROPERTIES RUNTIME_OUTPUT_DIRECTORY "${PROJECT_SOURCE_DIR}/src/")
    # alternatives considered:
    # add_file_dependencies, add_custom_target, add_custom_command
    add_dependencies(secp256k1 precomputation)
    if (TESTS)
        add_dependencies(test precomputation)
    endif()
    if (EXHAUSTIVE_TESTS)
        add_dependencies(exhaustive_test precomputation)
    endif()
    execute_process(COMMAND "${PROJECT_SOURCE_DIR}/src/precomputation" WORKING_DIRECTORY ${PROJECT_SOURCE_DIR})
endif()
