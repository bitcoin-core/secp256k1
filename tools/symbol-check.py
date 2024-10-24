#!/usr/bin/env python3
'''
A script to check that a libsecp256k1 shared library
exports only expected symbols.

Example usage:

- when building with Autotools:

    ./tools/symbol-check.py .libs/libsecp256k1.so
or
    ./tools/symbol-check.py .libs/libsecp256k1-<V>.dll
or
    ./tools/symbol-check.py .libs/libsecp256k1.dylib

- when building with CMake:

    ./tools/symbol-check.py build/lib/libsecp256k1.so
or
    ./tools/symbol-check.py build/bin/libsecp256k1-<V>.dll
or
    ./tools/symbol-check.py build/lib/libsecp256k1.dylib
'''
import re
import sys
import subprocess

import lief


def grep_exported_symbols() -> list[str]:
    grep_output = subprocess.check_output(["git", "grep", r"^\s*SECP256K1_API", "--", "include"], universal_newlines=True, encoding="utf8")
    lines = grep_output.split("\n")
    exports: list[str] = []
    pattern = re.compile(r'\bsecp256k1_\w+')
    for line in lines:
        if line.strip():
            function_name = pattern.findall(line)[-1]
            exports.append(function_name)
    return exports


def check_ELF_exported_symbols(library, expected_exports) -> bool:
    ok: bool = True
    for symbol in library.exported_symbols:
        name: str = symbol.name
        if name in expected_exports:
            continue
        print(f'{filename}: export of symbol {name} not expected')
        ok = False
    return ok


def check_PE_exported_functions(library, expected_exports) -> bool:
    ok: bool = True
    for function in library.exported_functions:
        name: str = function.name
        if name in expected_exports:
            continue
        print(f'{filename}: export of function {name} not expected')
        ok = False
    return ok


def check_MACHO_exported_functions(library, expected_exports) -> bool:
    ok: bool = True
    for function in library.exported_functions:
        name: str = function.name[1:]
        if name in expected_exports:
            continue
        print(f'{filename}: export of function {name} not expected')
        ok = False
    return ok


if __name__ == '__main__':
    filename: str = sys.argv[1]
    library: lief.Binary = lief.parse(filename)
    exe_format: lief.Binary.FORMATS = library.format
    if exe_format == lief.Binary.FORMATS.ELF:
        success = check_ELF_exported_symbols(library, grep_exported_symbols())
    elif exe_format == lief.Binary.FORMATS.PE:
        success = check_PE_exported_functions(library, grep_exported_symbols())
    elif exe_format == lief.Binary.FORMATS.MACHO:
        success = check_MACHO_exported_functions(library, grep_exported_symbols())

    if not success:
        sys.exit(1)
