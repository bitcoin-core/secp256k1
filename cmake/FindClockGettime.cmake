#[=======================================================================[
FindClockGettime
----------------

Finds the clock_gettime() POSIX function on the system.

Imported Targets
^^^^^^^^^^^^^^^^

This module provides the following Imported Targets:

POSIX::clock_gettime
  Target encapsulating the clock_gettime() usage requirements, available
  only if clock_gettime() is found.

#]=======================================================================]

include(CheckSymbolExists)
include(CMakePushCheckState)

cmake_push_check_state(RESET)

set(CMAKE_REQUIRED_DEFINITIONS -D_POSIX_C_SOURCE=199309L)
check_symbol_exists(clock_gettime "time.h" CLOCK_GETTIME_IS_BUILT_IN)
set(${CMAKE_FIND_PACKAGE_NAME}_FOUND ${CLOCK_GETTIME_IS_BUILT_IN})

if(NOT ${CMAKE_FIND_PACKAGE_NAME}_FOUND)
  set(CMAKE_REQUIRED_LIBRARIES rt)
  check_symbol_exists(clock_gettime "time.h" CLOCK_GETTIME_NEEDS_LINK_TO_LIBRT)
  set(${CMAKE_FIND_PACKAGE_NAME}_FOUND ${CLOCK_GETTIME_NEEDS_LINK_TO_LIBRT})
endif()

if(${CMAKE_FIND_PACKAGE_NAME}_FOUND)
  if(NOT TARGET POSIX::clock_gettime)
    add_library(POSIX::clock_gettime INTERFACE IMPORTED)
    set_target_properties(POSIX::clock_gettime PROPERTIES
      INTERFACE_COMPILE_DEFINITIONS "${CMAKE_REQUIRED_DEFINITIONS}"
      INTERFACE_LINK_LIBRARIES "${CMAKE_REQUIRED_LIBRARIES}"
    )
  endif()
else()
  if(${CMAKE_FIND_PACKAGE_NAME}_FIND_REQUIRED)
    message(FATAL_ERROR "clock_gettime() not available.")
  endif()
endif()

cmake_pop_check_state()
