#!/usr/bin/env bash
#
# Checks that frost header secp256k1_frost.h can be precompiled.
#
# What we would really like to do is trying to compile every header in the code
# base with this command:
#     gcc -Werror -pedantic-errors include/*.h
#     g++ -Werror -pedantic-errors include/*.h
#
# but that command would litter the working directory. We cannot directly use
# -o /dev/null because gcc does not support it for precompiled headers (see:
# https://gcc.gnu.org/bugzilla/show_bug.cgi?id=108732#c2), so we have to use
# this incantation.

set -u
set -e

SCRIPT_DIR=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )

errecho() {
    # prints to stderr
    >&2 echo "${@}"
}

log_info() {
    errecho "INFO: ${1}"
}

log_warning() {
    errecho "WARNING: ${1}"
}

log_error() {
    errecho "ERROR: ${1}"
}

checkPrerequisites() {
    if ! command -v gcc &> /dev/null
    then
        log_error "Please install gcc"
        exit 1
    fi
    if ! command -v g++ &> /dev/null
    then
        log_error "Please install g++"
        exit 1
    fi
}

checkPrerequisites

if [ "$#" -ne 1 ]; then
    log_error "You must enter exactly 1 command line argument ('c' or 'c++')"
    exit 1
fi

if [ "$1" != "c" ] && [ "$1" != "c++" ]; then
    log_error "USAGE: $0 <c|c++>"
    exit 1
fi

LANGUAGE="$1"

FROST_HEADER_PATH=$(realpath "${SCRIPT_DIR}/../include/secp256k1_frost.h")
log_info "Tryng to compile ${FROST_HEADER_PATH} with ${LANGUAGE}"

gcc -x"${LANGUAGE}" -c -Werror -pedantic-errors -include "${FROST_HEADER_PATH}" /dev/null -o /dev/null

log_info "OK (${LANGUAGE})"
