# Allow to easily build native executable.
# Useful for cross compilation.

# If we are cross compiling, create a directory for native build.
set(NATIVE_BUILD_DIR "${CMAKE_BINARY_DIR}/native" CACHE PATH "Path to the native build directory")
set(NATIVE_BINARY_DIR "${NATIVE_BUILD_DIR}/bin" CACHE PATH "Path to the native binary directory")
set(NATIVE_BUILD_TARGET "${NATIVE_BUILD_DIR}/CMakeCache.txt")

if(CMAKE_CROSSCOMPILING AND NOT TARGET native-cmake-build)
	file(MAKE_DIRECTORY ${NATIVE_BUILD_DIR})
	add_custom_command(
		OUTPUT ${NATIVE_BUILD_TARGET}
		COMMAND ${CMAKE_COMMAND}
			-G "${CMAKE_GENERATOR}"
			"${CMAKE_SOURCE_DIR}"
			"-DCMAKE_MAKE_PROGRAM=${CMAKE_MAKE_PROGRAM}"
			"-DCMAKE_RUNTIME_OUTPUT_DIRECTORY:PATH=${NATIVE_BINARY_DIR}"
		WORKING_DIRECTORY ${NATIVE_BUILD_DIR}
		VERBATIM USES_TERMINAL
	)

	add_custom_target(native-cmake-build DEPENDS ${NATIVE_BUILD_TARGET})
endif()

macro(add_native_executable NAME)
	if(CMAKE_CROSSCOMPILING)
		set(NATIVE_BINARY "${NATIVE_BINARY_DIR}/${NAME}")
		add_custom_target("build-native-${NAME}"
			COMMAND ${CMAKE_COMMAND}
				--build "${NATIVE_BUILD_DIR}"
				--target "${NAME}"
			DEPENDS ${NATIVE_BUILD_TARGET}
			BYPRODUCTS ${NATIVE_BINARY}
			WORKING_DIRECTORY ${NATIVE_BUILD_DIR}
			VERBATIM USES_TERMINAL
		)

		add_executable(${NAME} IMPORTED)
		add_dependencies(${NAME} "build-native-${NAME}")
		set_property(TARGET ${NAME} PROPERTY IMPORTED_LOCATION ${NATIVE_BINARY})
	else()
		add_executable(${NAME} EXCLUDE_FROM_ALL ${ARGN})
	endif(CMAKE_CROSSCOMPILING)
endmacro(add_native_executable)

function(native_target_include_directories)
	if(NOT CMAKE_CROSSCOMPILING)
		target_include_directories(${ARGN})
	endif(NOT CMAKE_CROSSCOMPILING)
endfunction(native_target_include_directories)
