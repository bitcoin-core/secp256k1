#!/usr/bin/env python3
# Copyright (c) 2014 Wladimir J. van der Laan
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
'''
A script to check that a secp256k1 shared library
exports only expected symbols.

Example usage:

    ./tools/symbol-check.py .libs/libsecp256k1.so.0.0.0
or
    ./tools/symbol-check.py .libs/libsecp256k1-0.dll
or
    ./tools/symbol-check.py .libs/libsecp256k1.0.dylib
'''
import re
import sys
import subprocess
from typing import List

import lief #type:ignore

def grep_exported_symbols() -> List[str]:
    grep_output = subprocess.check_output(["git", "grep", "^SECP256K1_API", "--", "include"], universal_newlines=True, encoding="utf8")
    lines = grep_output.split("\n")
    exports: List[str] = []
    pattern = re.compile(r'\bsecp256k1_\w+')
    for line in lines:
        if line.strip():
            function_name = pattern.findall(line)[-1]
            exports.append(function_name)
    return exports

def check_ELF_exported_symbols(library, expected_exports) -> bool:
    ok: bool = True
    elf_lib: lief.ELF.Binary = library.concrete

    for symbol in elf_lib.exported_symbols:
        name: str = symbol.name
        if name in expected_exports:
            continue
        print(f'{filename}: export of symbol {name} not expected')
        ok = False
    return ok

def check_PE_exported_functions(library, expected_exports) -> bool:
    ok: bool = True
    pe_lib: lief.PE.Binary = library.concrete

    for function in pe_lib.exported_functions:
        name: str = function.name
        if name in expected_exports:
            continue
        print(f'{filename}: export of function {name} not expected')
        ok = False
    return ok

def check_MACHO_exported_functions(library, expected_exports) -> bool:
    ok: bool = True
    macho_lib: lief.MACHO.Binary = library.concrete

    for function in macho_lib.exported_functions:
        name: str = function.name[1:]
        if name in expected_exports:
            continue
        print(f'{filename}: export of function {name} not expected')
        ok = False
    return ok

CHECKS = {
lief.EXE_FORMATS.ELF: [
    ('EXPORTED_SYMBOLS', check_ELF_exported_symbols),
],
lief.EXE_FORMATS.PE: [
    ('EXPORTED_FUNCTIONS', check_PE_exported_functions),
],
lief.EXE_FORMATS.MACHO: [
    ('EXPORTED_FUNCTIONS', check_MACHO_exported_functions),
]
}

USAGE = """
symbol-check.py is a script to check that a secp256k1 shared library
exports only expected symbols.

Usage:
    ./tools/symbol-check.py <library>

"""

if __name__ == '__main__':
    if len(sys.argv) != 2:
        sys.exit(USAGE)

    filename: str = sys.argv[1]
    try:
        library: lief.Binary = lief.parse(filename)
        exe_format: lief.EXE_FORMATS = library.format
        if exe_format == lief.EXE_FORMATS.UNKNOWN:
            print(f'{filename}: unknown executable format')
            sys.exit(1)

        obj_type = library.abstract.header.object_type
        if obj_type != lief.OBJECT_TYPES.LIBRARY:
            print(f'{filename}: unsupported object type, only LIBRARY type is supported')
            sys.exit(1)

        expected_exports = grep_exported_symbols()
        failed: List[str] = []
        for (name, func) in CHECKS[exe_format]:
            if not func(library, expected_exports):
                failed.append(name)
        if failed:
            print(f'{filename}: failed {" ".join(failed)}')
            sys.exit(1)
    except IOError:
        print(f'{filename}: cannot open')
        sys.exit(1)
