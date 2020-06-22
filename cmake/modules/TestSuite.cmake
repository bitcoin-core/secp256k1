# Allow to easily build test suites

macro(create_test_suite NAME)
	enable_testing()
	set(TARGET "check-${NAME}")
	add_custom_target(${TARGET} COMMAND ${CMAKE_CTEST_COMMAND})

	# If the magic target check-all exists, attach to it.
	if(TARGET check-all)
		add_dependencies(check-all ${TARGET})
	endif()
endmacro(create_test_suite)

function(add_test_to_suite SUITE NAME)
	add_executable(${NAME} EXCLUDE_FROM_ALL ${ARGN})
	add_test(${NAME} ${NAME})
	add_dependencies("check-${SUITE}" ${NAME})
endfunction(add_test_to_suite)
