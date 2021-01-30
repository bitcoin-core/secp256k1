#!/bin/sh

set -e
set -x

export LC_ALL=C

env >> test_env.log

$CC -v || true
valgrind --version || true

./autogen.sh

# Nix doesn't store GNU file in /usr/bin, see https://lists.gnu.org/archive/html/bug-libtool/2015-09/msg00000.html .
# The -i'' is necessary for macOS portability, see https://stackoverflow.com/a/4247319 .
sed -i'' -e 's@/usr/bin/file@$(which file)@g' configure

./configure \
    --enable-experimental="$EXPERIMENTAL" \
    --with-test-override-wide-multiply="$WIDEMUL" --with-bignum="$BIGNUM" --with-asm="$ASM" \
    --enable-ecmult-static-precomputation="$STATICPRECOMPUTATION" --with-ecmult-gen-precision="$ECMULTGENPRECISION" \
    --enable-module-ecdh="$ECDH" --enable-module-recovery="$RECOVERY" \
    --enable-module-schnorrsig="$SCHNORRSIG" \
    --with-valgrind="$WITH_VALGRIND" \
    --host="$HOST" $EXTRAFLAGS

if [ -n "$BUILD" ]
then
    make -j2 "$BUILD"
fi

if [ "$RUN_VALGRIND" = "yes" ]
then
    make -j2
    # the `--error-exitcode` is required to make the test fail if valgrind found errors, otherwise it'll return 0 (https://www.valgrind.org/docs/manual/manual-core.html)
    valgrind --error-exitcode=42 ./tests 16
    valgrind --error-exitcode=42 ./exhaustive_tests
fi

if [ -n "$QEMU_CMD" ]
then
    make -j2
    $QEMU_CMD ./tests 16
    $QEMU_CMD ./exhaustive_tests
fi

if [ "$BENCH" = "yes" ]
then
    # Using the local `libtool` because on macOS the system's libtool has nothing to do with GNU libtool
    EXEC='./libtool --mode=execute'
    if [ -n "$QEMU_CMD" ]
    then
       EXEC="$EXEC $QEMU_CMD"
    fi
    if [ "$RUN_VALGRIND" = "yes" ]
    then
        EXEC="$EXEC valgrind --error-exitcode=42"
    fi
    # This limits the iterations in the benchmarks below to ITER iterations.
    export SECP256K1_BENCH_ITERS="$ITERS"
    {
        $EXEC ./bench_ecmult
        $EXEC ./bench_internal
        $EXEC ./bench_sign
        $EXEC ./bench_verify
    } >> bench.log 2>&1
    if [ "$RECOVERY" = "yes" ]
    then
        $EXEC ./bench_recover >> bench.log 2>&1
    fi
    if [ "$ECDH" = "yes" ]
    then
        $EXEC ./bench_ecdh >> bench.log 2>&1
    fi
    if [ "$SCHNORRSIG" = "yes" ]
    then
        $EXEC ./bench_schnorrsig >> bench.log 2>&1
    fi
fi
if [ "$CTIMETEST" = "yes" ]
then
    ./libtool --mode=execute valgrind --error-exitcode=42 ./valgrind_ctime_test > valgrind_ctime_test.log 2>&1
fi
