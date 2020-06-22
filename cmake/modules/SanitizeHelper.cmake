# Sanitize a variable according to cmake rules
# https://cmake.org/cmake/help/v3.10/manual/cmake-language.7.html#variable-references
# The NUL and ';' characters cannot be escaped in this context (see CMP0053)
macro(sanitize_variable PREFIX RAW_VAR SANITIZED_VAR)
	# Escaping characters not in the supported list (see documentation) will
	# work as long as the variable is not cached.
	
	# Variable caching is achieved by writing the variable to a CMakeCache.txt
	# file, where the escaped chars get interpreted. The issue occurs when the
	# cache is read, as the chars are not getting escaped again and cause the
	# read to fail.
	
	# The safe way to sanitize a variable is not to escape these chars, but
	# rather to replace them with a known supported one, here '_' is chosen.
	# Not: this could lead to name collision in some rare case. These case can
	# be handled manually by using a different prefix.
	string(REGEX REPLACE
		"([^a-zA-Z0-9/_.+-])" "_" ${SANITIZED_VAR} "${PREFIX}${RAW_VAR}")
endmacro()
