/*************************************************************************
 * Copyright (c) 2020-2021 Elichai Turkel                                *
 * Distributed under the CC0 software license, see the accompanying file *
 * EXAMPLES_COPYING or https://creativecommons.org/publicdomain/zero/1.0 *
 *************************************************************************/

/*
 * This file is an attempt at collecting best practice methods for obtaining randomness with different operating systems.
 * It may be out-of-date. Consult the documentation of the operating system before considering to use the methods below.
 *
 * Platform randomness sources:
 * Linux   -> `getrandom(2)`(`sys/random.h`), if not available `/dev/urandom` should be used. http://man7.org/linux/man-pages/man2/getrandom.2.html, https://linux.die.net/man/4/urandom
 *            (glibc >= 2.36 also provides `arc4random_buf(3)`, but musl and older versions of glibc don't.)
 * macOS   -> `CCRandomGenerateBytes`(`CommonCrypto/CommonRandom.h`). https://github.com/apple-oss-distributions/CommonCrypto/blob/CommonCrypto-600035/include/CommonRandom.h
 * FreeBSD -> `arc4random_buf(3)`(`stdlib.h`). https://man.freebsd.org/cgi/man.cgi?query=arc4random_buf
 * NetBSD  -> `arc4random_buf(3)`(`stdlib.h`). https://man.netbsd.org/arc4random.3
 * OpenBSD -> `arc4random_buf(3)`(`stdlib.h`). https://man.openbsd.org/arc4random.3
 * Windows -> `BCryptGenRandom`(`bcrypt.h`). https://docs.microsoft.com/en-us/windows/win32/api/bcrypt/nf-bcrypt-bcryptgenrandom
 */

#if defined(_WIN32)
/*
 * The defined WIN32_NO_STATUS macro disables return code definitions in
 * windows.h, which avoids "macro redefinition" MSVC warnings in ntstatus.h.
 */
#define WIN32_NO_STATUS
#include <windows.h>
#undef WIN32_NO_STATUS
#include <ntstatus.h>
#include <bcrypt.h>
#elif defined(__linux__)
#include <errno.h>
#include <sys/random.h>
#elif defined(__APPLE__)
#include <CommonCrypto/CommonRandom.h>
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
/* `arc4random_buf(3)` is declared in `stdlib.h`, which is included below. */
#else
#error "Couldn't identify the OS"
#endif

#include <stddef.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>


/* Fills `data` with `size` random bytes and returns 1. Aborts on failure.
 *
 * Even though this function never returns 0, it has `return 0` after every
 * `abort()`, and the examples check its return value. This keeps the code
 * correct if `abort()` is replaced by something that returns, or if the
 * examples are combined with a variant of this function that returns 0 on
 * failure. */
static int fill_random(unsigned char* data, size_t size) {
#if defined(_WIN32)
    /* `BCryptGenRandom` takes a ULONG length, so split larger requests. */
    while (size > 0) {
        ULONG chunk = size < ULONG_MAX ? (ULONG)size : ULONG_MAX;
        NTSTATUS res = BCryptGenRandom(NULL, data, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
        if (res != STATUS_SUCCESS) {
            fprintf(stderr, "Failed to generate randomness\n");
            abort();
            return 0;
        }
        data += chunk;
        size -= chunk;
    }
#elif defined(__linux__)
    /* If `getrandom(2)` is not available you should fallback to /dev/urandom */
    while (size > 0) {
        /* `getrandom(2)` may return fewer bytes than requested (for requests
         * larger than 256 bytes) or fail with EINTR (if interrupted by a
         * signal), so call it until done. */
        ssize_t res = getrandom(data, size, 0);
        if (res < 0 && errno == EINTR) {
            continue;
        }
        if (res <= 0) {
            fprintf(stderr, "Failed to generate randomness\n");
            abort();
            return 0;
        }
        data += res;
        size -= (size_t)res;
    }
#elif defined(__APPLE__)
    if (CCRandomGenerateBytes(data, size) != kCCSuccess) {
        fprintf(stderr, "Failed to generate randomness\n");
        abort();
        return 0;
    }
#elif defined(__FreeBSD__) || defined(__NetBSD__) || defined(__OpenBSD__)
    /* `arc4random_buf(3)` never returns an error and works for arbitrary sizes. */
    arc4random_buf(data, size);
#endif
    return 1;
}

static void print_hex(unsigned char* data, size_t size) {
    size_t i;
    printf("0x");
    for (i = 0; i < size; i++) {
        printf("%02x", data[i]);
    }
    printf("\n");
}

#if defined(_MSC_VER)
// For SecureZeroMemory
#include <Windows.h>
#endif
/* Cleanses memory to prevent leaking sensitive info. Won't be optimized out. */
static void secure_erase(void *ptr, size_t len) {
#if defined(_MSC_VER)
    /* SecureZeroMemory is guaranteed not to be optimized out by MSVC. */
    SecureZeroMemory(ptr, len);
#elif defined(__GNUC__)
    /* We use a memory barrier that scares the compiler away from optimizing out the memset.
     *
     * Quoting Adam Langley <agl@google.com> in commit ad1907fe73334d6c696c8539646c21b11178f20f
     * in BoringSSL (ISC License):
     *    As best as we can tell, this is sufficient to break any optimisations that
     *    might try to eliminate "superfluous" memsets.
     * This method used in memzero_explicit() the Linux kernel, too. Its advantage is that it is
     * pretty efficient, because the compiler can still implement the memset() efficiently,
     * just not remove it entirely. See "Dead Store Elimination (Still) Considered Harmful" by
     * Yang et al. (USENIX Security 2017) for more background.
     */
    memset(ptr, 0, len);
    __asm__ __volatile__("" : : "r"(ptr) : "memory");
#else
    void *(*volatile const volatile_memset)(void *, int, size_t) = memset;
    volatile_memset(ptr, 0, len);
#endif
}
