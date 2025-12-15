/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_TESTS_COMMON_H
#define SECP256K1_TESTS_COMMON_H

/***********************************************************************
 * Test Support Utilities
 *
 * This file provides general-purpose functions for tests and benchmark
 * programs. Unlike testutil.h, this file is not linked to the library,
 * allowing each program to choose whether to run against the production
 * API or access library internals directly.
 ***********************************************************************/

#include <stdint.h>

#if defined(_WIN32)
# include <windows.h>
#else /* POSIX */
# include <time.h>
#endif

static int64_t gettime_us(void) {
#if defined(_WIN32)

    LARGE_INTEGER freq, counter;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&counter);
    return (int64_t)(counter.QuadPart * 1000000 / freq.QuadPart);

#else /* POSIX */

# if defined(CLOCK_PROCESS_CPUTIME_ID)
    /* In theory, CLOCK_PROCESS_CPUTIME_ID is only useful if the process is locked to a core,
     * see `man clock_gettime` on Linux. In practice, modern CPUs have synchronized TSCs which
     * address this issue, see https://docs.amd.com/r/en-US/ug1586-onload-user/Timer-TSC-Stability . */
    const clockid_t clock_type = CLOCK_PROCESS_CPUTIME_ID;
# elif defined(CLOCK_MONOTONIC)
    /* fallback to global timer */
    const clockid_t clock_type = CLOCK_MONOTONIC;
# else
    /* fallback to wall-clock timer */
    const clockid_t clock_type = CLOCK_REALTIME;
# endif

    struct timespec ts;
    clock_gettime(clock_type, &ts);
    return (int64_t)ts.tv_sec * 1000000 + ts.tv_nsec / 1000;
#endif
}

#endif /* SECP256K1_TESTS_COMMON_H */
