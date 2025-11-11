#----------------------------------------------------------------
# Generated CMake target import file for configuration "Release".
#----------------------------------------------------------------

# Commands may need to know the format version.
set(CMAKE_IMPORT_FILE_VERSION 1)

# Import target "libsecp256k1::secp256k1" for configuration "Release"
set_property(TARGET libsecp256k1::secp256k1 APPEND PROPERTY IMPORTED_CONFIGURATIONS RELEASE)
set_target_properties(libsecp256k1::secp256k1 PROPERTIES
  IMPORTED_LOCATION_RELEASE "${_IMPORT_PREFIX}/lib/libsecp256k1.so.6.0.1"
  IMPORTED_SONAME_RELEASE "libsecp256k1.so.6"
  )

list(APPEND _cmake_import_check_targets libsecp256k1::secp256k1 )
list(APPEND _cmake_import_check_files_for_libsecp256k1::secp256k1 "${_IMPORT_PREFIX}/lib/libsecp256k1.so.6.0.1" )

# Commands beyond this point should not need to know the version.
set(CMAKE_IMPORT_FILE_VERSION)
