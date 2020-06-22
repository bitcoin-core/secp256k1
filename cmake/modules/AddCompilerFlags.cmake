# Allow to easily add flags for C and C++
include(CheckCXXCompilerFlag)
include(CheckCCompilerFlag)
include(SanitizeHelper)

function(check_compiler_flag RESULT LANGUAGE FLAG)
	sanitize_variable("have_${LANGUAGE}_" ${FLAG} TEST_NAME)

	if("${LANGUAGE}" STREQUAL "C")
		CHECK_C_COMPILER_FLAG(${FLAG} ${TEST_NAME})
	elseif("${LANGUAGE}" STREQUAL "CXX")
		CHECK_CXX_COMPILER_FLAG(${FLAG} ${TEST_NAME})
	else()
		message(FATAL_ERROR "check_compiler_flag LANGUAGE should be C or CXX")
	endif()
	set(${RESULT} ${${TEST_NAME}} PARENT_SCOPE)
endfunction()

function(add_c_compiler_flag)
	foreach(f ${ARGN})
		check_compiler_flag(FLAG_IS_SUPPORTED C ${f})
		if(${FLAG_IS_SUPPORTED})
			string(APPEND CMAKE_C_FLAGS " ${f}")
		endif()
	endforeach()
	set(CMAKE_C_FLAGS ${CMAKE_C_FLAGS} PARENT_SCOPE)
endfunction()

function(add_cxx_compiler_flag)
	foreach(f ${ARGN})
		check_compiler_flag(FLAG_IS_SUPPORTED CXX ${f})
		if(${FLAG_IS_SUPPORTED})
			string(APPEND CMAKE_CXX_FLAGS " ${f}")
		endif()
	endforeach()
	set(CMAKE_CXX_FLAGS ${CMAKE_CXX_FLAGS} PARENT_SCOPE)
endfunction()

macro(add_compiler_flag)
	add_c_compiler_flag(${ARGN})
	add_cxx_compiler_flag(${ARGN})
endmacro()

macro(remove_c_compiler_flags)
	if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
		string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
		set(BUILD_TYPE_C_FLAGS "CMAKE_C_FLAGS_${BUILD_TYPE}")
	endif()
	
	foreach(f ${ARGN})
		string(REGEX REPLACE "${f}( |$)" "" CMAKE_C_FLAGS "${CMAKE_C_FLAGS}")
		if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
			string(REGEX REPLACE "${f}( |$)" "" ${BUILD_TYPE_C_FLAGS} "${${BUILD_TYPE_C_FLAGS}}")
		endif()
	endforeach()
endmacro()

macro(remove_cxx_compiler_flags)
	if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
		string(TOUPPER ${CMAKE_BUILD_TYPE} BUILD_TYPE)
		set(BUILD_TYPE_CXX_FLAGS "CMAKE_CXX_FLAGS_${BUILD_TYPE}")
	endif()
	
	foreach(f ${ARGN})
		string(REGEX REPLACE "${f}( |$)" "" CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS}")
		if(NOT "${CMAKE_BUILD_TYPE}" STREQUAL "")
			string(REGEX REPLACE "${f}( |$)" "" ${BUILD_TYPE_CXX_FLAGS} "${${BUILD_TYPE_CXX_FLAGS}}")
		endif()
	endforeach()
endmacro()

macro(remove_compiler_flags)
	remove_c_compiler_flags(${ARGN})
	remove_cxx_compiler_flags(${ARGN})
endmacro()

function(add_cxx_compiler_flag_with_fallback TARGET_VAR FLAG FALLBACK)
	# Remove the fallback flag if it exists, so that the main flag will override
	# it if it was previously added.
	remove_cxx_compiler_flags(${FALLBACK})
	
	set(FLAG_CANDIDATE ${FLAG})
	check_compiler_flag(FLAG_IS_SUPPORTED CXX ${FLAG_CANDIDATE})
	if(NOT ${FLAG_IS_SUPPORTED})
		set(FLAG_CANDIDATE ${FALLBACK})
		check_compiler_flag(FLAG_IS_SUPPORTED CXX ${FLAG_CANDIDATE})
	endif()
	
	if(${FLAG_IS_SUPPORTED})
		string(APPEND ${TARGET_VAR} " ${FLAG_CANDIDATE}")
		set(${TARGET_VAR} ${${TARGET_VAR}} PARENT_SCOPE)
	endif()
endfunction()

# Note that CMake does not provide any facility to check that a linker flag is
# supported by the compiler.
# However since CMake 3.2 introduced the CMP0056 policy, the
# CMAKE_EXE_LINKER_FLAGS variable is used by the try_compile function, so there
# is a workaround that allow for testing the linker flags.
function(add_linker_flag)
	foreach(f ${ARGN})
		sanitize_variable("have_linker_" ${f} FLAG_IS_SUPPORTED)
		
		# Save the current linker flags
		set(SAVE_CMAKE_EXE_LINKERFLAGS ${CMAKE_EXE_LINKER_FLAGS})
		string(APPEND CMAKE_EXE_LINKER_FLAGS " ${f}")
		# CHECK_CXX_COMPILER_FLAG calls CHECK_CXX_SOURCE_COMPILES which in turn
		# calls try_compile, so it will check our flag
		CHECK_CXX_COMPILER_FLAG("" ${FLAG_IS_SUPPORTED})
		
		# If the flag is not supported restore CMAKE_EXE_LINKER_FLAGS
		if(NOT ${FLAG_IS_SUPPORTED})
			set(CMAKE_EXE_LINKER_FLAGS ${SAVE_CMAKE_EXE_LINKERFLAGS})
		endif()
	endforeach()
	set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} PARENT_SCOPE)
endfunction()
