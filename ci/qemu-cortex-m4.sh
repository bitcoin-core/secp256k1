#!/bin/sh

# Run a bare metal ELF binary on an emulated ARM Cortex-M4 microcontroller.
#
# Usage: qemu-cortex-m4.sh <binary> [<arg>...]
#
# The machine is the Olimex STM32-H405 board, which is built around the
# STM32F405 microcontroller (Cortex-M4, 1 MiB of flash memory, 128 KiB of
# SRAM).
#
# There is no OS on the target. The binary is expected to be linked against
# a libc that implements I/O via ARM semihosting (e.g., picolibc with
# --oslib=semihost). QEMU then forwards stdout/stderr, file access, the
# command line arguments and the exit code between the target and the host.
# Environment variables are not forwarded.
#
# If QEMU_TESTS_ARGS is set, its (whitespace-separated) contents are appended
# to the arguments of the "tests" and "noverify_tests" binaries. This makes
# it possible to pass arguments to them when they are run by "make check".

set -eu

QEMU=qemu-system-arm

if [ "${1:-}" = "--version" ]; then
    exec "$QEMU" --version
fi

case "$(basename "$1")" in
    tests|noverify_tests)
        # shellcheck disable=SC2086
        set -- "$@" ${QEMU_TESTS_ARGS:-}
        ;;
esac

# The first semihosting argument is argv[0]. Commas need to be escaped by
# doubling them in QEMU option values.
semihosting_config="enable=on,target=native"
for arg in "$@"; do
    semihosting_config="$semihosting_config,arg=$(printf '%s' "$arg" | sed 's/,/,,/g')"
done

exec "$QEMU" -machine olimex-stm32-h405 -nographic -monitor none -serial none \
    -semihosting-config "$semihosting_config" -kernel "$1"
