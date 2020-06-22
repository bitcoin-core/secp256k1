# Try to find the GMP libraries
# GMP_FOUND - system has GMP lib
# GMP_INCLUDE_DIR - the GMP include directory
# GMP_LIBRARY - Library needed to use GMP
# GMPXX_LIBRARY - Library needed to use GMP C++ API

if(GMP_INCLUDE_DIR AND GMP_LIBRARY)
	# Already in cache, be silent
	set(GMP_FIND_QUIETLY TRUE)
endif()

find_path(GMP_INCLUDE_DIR NAMES gmp.h)
find_library(GMP_LIBRARY NAMES gmp libgmp)
find_library(GMPXX_LIBRARY NAMES gmpxx libgmpxx)

message(STATUS "GMP libs: " ${GMP_LIBRARY} " " ${GMPXX_LIBRARY})

include(FindPackageHandleStandardArgs)
find_package_handle_standard_args(GMP DEFAULT_MSG GMP_INCLUDE_DIR GMP_LIBRARY)

mark_as_advanced(GMP_INCLUDE_DIR GMP_LIBRARY GMPXX_LIBRARY)

set(GMP_LIBRARIES ${GMP_LIBRARY} ${GMPXX_LIBRARY})
set(GMP_INCLUDE_DIRS ${GMP_INCLUDE_DIR})
