#!/bin/sh

set -u

for header in "$@"; do
    source_file=${header%.h}.c
    object_file=${header%.h}.o
    mv "$header" "$source_file"
    gcc -c "$source_file" -o "$object_file"
    exit_code=$?
    mv "$source_file" "$header"
    if [ $exit_code -ne 0 ]; then
        exit $exit_code
    fi
    echo "$header... OK"
done
