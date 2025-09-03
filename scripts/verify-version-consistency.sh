#!/usr/bin/env bash
#
# This project supports two build systems: autotools and CMake.
# Each of them declares a project version.
#
# This script verifies that:
# - the versions contained in CMakeLists.txt and configure.ac are the same

set -u
set -o errtrace
set -o pipefail

# source: https://stackoverflow.com/questions/59895/how-do-i-get-the-directory-where-a-bash-script-is-located-from-within-the-script/246128#246128
MY_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

BASE_DIR=$(realpath "${MY_DIR}/..")
BUILD_DIR=$(mktemp --tmpdir --directory secp256k1-frost-build.XXXX)
CONFIGURE_AC=$(realpath --canonicalize-existing "${BASE_DIR}/configure.ac")

errecho() {
    # prints to stderr
    >&2 echo "${@}"
}

log_error() {
    errecho "ERROR: $1"
}

log_debug() {
    errecho "DEBUG: $1"
}

log_info() {
    errecho "INFO: $1"
}

handle_error() {
    local EXIT_CODE
    EXIT_CODE=$1 && shift
    log_error "exiting on unexpected error ${EXIT_CODE}"
    exit "${EXIT_CODE}"
}

trap 'handle_error $?' ERR

check_prerequisites() {
    if ! command -v cmake &> /dev/null; then
        log_error "Please install cmake"
        exit 1
    fi
    if ! command -v gawk &> /dev/null; then
        log_error "Please install gawk"
        exit 1
    fi
    if ! command -v realpath &> /dev/null; then
        log_error "The realpath command is not available"
        exit 1
    fi
}

extract_from_configure_ac() {
    # $1: variable part of the regex defining the field to be matched
    # $2: if true, also require that the extracted string is a number
    #
    # Reads the global variable CONFIGURE_AC and interprets it as a file name.
    local EXTRACTED_NUMBER
    local REQUIRE_NUMERIC_FORMAT
    EXTRACTED_NUMBER=$(gawk "match(\$0, /define\(${1}, ([^\)]*)\)/, a) { print a[1] }" "${CONFIGURE_AC}")
    REQUIRE_NUMERIC_FORMAT="${2:-true}"
    if [[ "${REQUIRE_NUMERIC_FORMAT}" == true ]] && ! [[ "${EXTRACTED_NUMBER}" =~ ^[0-9]+$ ]]; then
        log_error "could not extract field $1 from ${CONFIGURE_AC}. The value that was found (\"${EXTRACTED_NUMBER}\") is not a number"
        exit 1
    fi
    echo "${EXTRACTED_NUMBER}"
}

extract_from_cmake() {
    # $1: variable part of the regex defining the field to be matched
    # $2: if true, also require that the extracted string is a number
    #
    # Reads the global variable SYSTEM_INFORMATION and use it as the text to
    # search into.
    local EXTRACTED_NUMBER
    local REQUIRE_NUMERIC_FORMAT
    EXTRACTED_NUMBER=$(gawk -F= "\$1~/$1/{print\$2}" - <<<"${SYSTEM_INFORMATION}")
    REQUIRE_NUMERIC_FORMAT="${2:-true}"
    if [[ "${REQUIRE_NUMERIC_FORMAT}" == true ]] && ! [[ "${EXTRACTED_NUMBER}" =~ ^[0-9]+$ ]]; then
        log_error "could not extract field $1 from ${BUILD_DIR}/CMakeCache.txt. The value that was found (\"${EXTRACTED_NUMBER}\") is not a number. Check your CMakeLists.txt"
        exit 1
    fi
    echo "${EXTRACTED_NUMBER}"
}

check_equal() {
    # $1: version in configure.ac
    # $2: version in CMakeLists.txt
    # $3: human-friendly field name (e.g., "MAJOR_VERSION") to use in the
    #     eventual error message
    if [[ "${1}" != "${2}" ]]; then
        log_error "field \"${3}\" in configure.ac (\"${1}\") is different than the one in CMakeLists.txt (\"${2}\")"
        exit 1
    fi
}

check_prerequisites

# gather version data from configure.ac
AC_VERSION_MAJOR=$(extract_from_configure_ac _PKG_VERSION_MAJOR)
AC_VERSION_MINOR=$(extract_from_configure_ac _PKG_VERSION_MINOR)
AC_VERSION_PATCH=$(extract_from_configure_ac _PKG_VERSION_PATCH)
AC_VERSION_FROST=$(extract_from_configure_ac _PKG_VERSION_FROST_BUILD)
AC_VERSION_FULL="${AC_VERSION_MAJOR}.${AC_VERSION_MINOR}.${AC_VERSION_PATCH}.${AC_VERSION_FROST}"
log_info "version found in configure.ac is: \"${AC_VERSION_FULL}\""

# gather version data from CMakeLists.txt
cmake --log-level=error -S "${BASE_DIR}" -B "${BUILD_DIR}" >/dev/null
# shellcheck disable=SC2164
pushd "${BUILD_DIR}" >/dev/null
SYSTEM_INFORMATION=$(cmake --system-information -N)
# shellcheck disable=SC2164
popd >/dev/null

CMAKE_PROJECT_VERSION_MAJOR=$(extract_from_cmake "CMAKE_PROJECT_VERSION_MAJOR:STATIC")
CMAKE_PROJECT_VERSION_MINOR=$(extract_from_cmake "CMAKE_PROJECT_VERSION_MINOR:STATIC")
CMAKE_PROJECT_VERSION_PATCH=$(extract_from_cmake "CMAKE_PROJECT_VERSION_PATCH:STATIC")
CMAKE_PROJECT_VERSION_TWEAK=$(extract_from_cmake "CMAKE_PROJECT_VERSION_TWEAK:STATIC")
CMAKE_PROJECT_VERSION=$(extract_from_cmake "CMAKE_PROJECT_VERSION:STATIC" false)
log_info "version found in CMakeLists.txt is: \"${CMAKE_PROJECT_VERSION}\""

# check that configure.ac and CMakeLists.txt contain the same information
check_equal "${AC_VERSION_MAJOR}" "${CMAKE_PROJECT_VERSION_MAJOR}" "major version"
check_equal "${AC_VERSION_MINOR}" "${CMAKE_PROJECT_VERSION_MINOR}" "minor version"
check_equal "${AC_VERSION_PATCH}" "${CMAKE_PROJECT_VERSION_PATCH}" "patch version"
check_equal "${AC_VERSION_FROST}" "${CMAKE_PROJECT_VERSION_TWEAK}" "frost version"
check_equal "${AC_VERSION_FULL}" "${CMAKE_PROJECT_VERSION}" "full frost version"

echo "SUCCESS: identified version ${AC_VERSION_FULL}"
