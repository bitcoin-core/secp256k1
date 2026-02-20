function(precompute base_name)
  add_executable(secp256k1_precompute_${base_name} EXCLUDE_FROM_ALL precompute_${base_name}.c)
  set_target_properties(secp256k1_precompute_${base_name} PROPERTIES
    COMPILE_DEFINITIONS VERIFY
    RUNTIME_OUTPUT_DIRECTORY ${PROJECT_BINARY_DIR}
  )
  add_custom_command(
    OUTPUT ${PROJECT_BINARY_DIR}/src/precomputed_${base_name}.c
    COMMAND secp256k1_precompute_${base_name}
    DEPENDS secp256k1_precompute_${base_name}
    WORKING_DIRECTORY ${PROJECT_BINARY_DIR}
  )
endfunction()
