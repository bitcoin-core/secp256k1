#!/bin/sh

set -e
set -x

SRC_PATH="$1"
TAG="$2"

if [ -z "${SRC_PATH}" ]; then
    echo "Usage: alpine_install.sh <src path> [<git tag>]"
    echo "  If no repo exists at the path, one will be cloned."
    exit 1
fi

apk add libtool clang make musl-dev autoconf automake gcc
export CC=clang

if [ ! -d "${SRC_PATH}" ]; then
    apk add git
    BRANCH=''
    [ ! -z "${TAG}" ] && BRANCH="-b ${TAG}"
    git clone ${BRANCH} https://github.com/bitcoin-core/secp256k1 "${SRC_PATH}" 
fi

cd "${SRC_PATH}"

./autogen.sh
./configure
make
make check
make install
