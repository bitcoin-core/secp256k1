#!/bin/sh

set -eu

builddir=$(mktemp -d)
trap 'rm -rf "$builddir"' EXIT INT TERM

for header in "$@"; do
    source_file="${builddir}/${header%.h}.c"
    object_file="${builddir}/${header%.h}.o"
    mkdir -p "$(dirname "$source_file")"
    cp "$header" "$source_file"

    cc -I include -I src -c "$source_file" -o "$object_file"
    exit_code=$?
    if [ $exit_code -ne 0 ]; then
        exit $exit_code
    fi

    echo "$header... OK"
done
