include_guard(GLOBAL)

include(CheckCSourceCompiles)

function(secp256k1_check_linker_flags_internal flags output)
  string(MAKE_C_IDENTIFIER "${flags}" result)
  string(TOUPPER "${result}" result)
  set(result "LINKER_SUPPORTS_${result}")
  set(CMAKE_REQUIRED_FLAGS "${flags}")
  if(MSVC)
    string(APPEND " /WX")
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Darwin")
    string(APPEND " -Wl,-fatal_warnings")
  else()
    string(APPEND " -Wl,--fatal-warnings")
  endif()

  # This ensures running a linker.
  set(CMAKE_TRY_COMPILE_TARGET_TYPE EXECUTABLE)
  check_c_source_compiles("int main() { return 0; }" ${result})

  set(${output} ${${result}} PARENT_SCOPE)
endfunction()

# Append flags to the LINK_OPTIONS directory property if a linker accepts them.
macro(try_append_linker_flags)
  secp256k1_check_linker_flags_internal("${ARGV}" result)
  if(result)
    add_link_options(${ARGV})
  endif()
  unset(result)
endmacro()
