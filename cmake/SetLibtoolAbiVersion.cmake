# This emulates Libtool to make sure Libtool and CMake agree on the ABI version,
# see below "Calculate the version variables" in autotools-aux/ltmain.sh.
function(set_libtool_abi_version target current revision age)
  math(EXPR _soversion "${current} - ${age}")
  set_target_properties(${target} PROPERTIES
    SOVERSION ${_soversion}
  )
  if(CMAKE_SYSTEM_NAME MATCHES "^(Linux|FreeBSD)$")
    set_target_properties(${target} PROPERTIES
      VERSION ${_soversion}.${age}.${revision}
    )
  elseif(APPLE)
    math(EXPR _compatibility "${current} + 1")
    set_target_properties(${target} PROPERTIES
      MACHO_COMPATIBILITY_VERSION ${_compatibility}
      MACHO_CURRENT_VERSION ${_compatibility}.${revision}
    )
  elseif(CMAKE_SYSTEM_NAME STREQUAL "Windows")
    set(_windows_name "secp256k1")
    if(MSVC)
      set(_windows_name "${PROJECT_NAME}")
    endif()
    set_target_properties(${target} PROPERTIES
      ARCHIVE_OUTPUT_NAME "${_windows_name}"
      RUNTIME_OUTPUT_NAME "${_windows_name}-${_soversion}"
    )
  endif()
endfunction()
