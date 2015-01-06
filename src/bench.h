/**********************************************************************
 * Copyright (c) 2014 Pieter Wuille                                   *
 * Distributed under the MIT software license, see the accompanying   *
 * file COPYING or http://www.opensource.org/licenses/mit-license.php.*
 **********************************************************************/

#ifndef _SECP256K1_BENCH_H_
#define _SECP256K1_BENCH_H_

#include <unistd.h>
#include <getopt.h>
#include <stdio.h>
#include <math.h>
#include "sys/time.h"

static double gettimedouble(void) {
    struct timeval tv;
    gettimeofday(&tv, NULL);
    return tv.tv_usec * 0.000001 + tv.tv_sec;
}

void run_benchmark(void (*benchmark)(void*,unsigned int), void (*setup)(void*), void (*teardown)(void*), void* data, int count, int iters) {
    double min = HUGE_VAL;
    double sum = 0.0;
    double max = 0.0;
    for (int i = 0; i < count; i++) {
        if (setup) setup(data);
        double begin = gettimedouble();
        benchmark(data, iters);
        double total = gettimedouble() - begin;
        if (teardown) teardown(data);
        if (total < min) min = total;
        if (total > max) max = total;
        sum += total;
    }
    printf("min %.3fus / avg %.3fus / max %.3fus\n", min * 1000000.0 / iters, (sum / count) * 1000000.0 / iters, max * 1000000.0 / iters);
}

void parse_bench_args(int argc, char **argv, int *iters, int *count, int *tablesize) {
    int oa;

    while ((oa = getopt(argc, argv, "c:i:w:")) != -1) {
        switch (oa) {
        case 'c':
            *count=atoi(optarg);
            ( *count<0 || *count > 5000 ) ? (printf("Count %d out of sane bounds. Resetting to 10.\n",*count),(*count=10)):0x0;
            break;
        case 'i':
            *iters=atoi(optarg);
            ( *iters<0 || *iters > 200000 ) ? (printf("Iterations %d out of sane bounds. Resetting to 20000.\n",*iters),*iters=20000):0x0;
            break;
        case 'w':
            *tablesize=atoi(optarg);
            ( *tablesize<2 || *tablesize > 30) ? (printf("WINDOW_G cache %d out of sane bounds. Resetting to 16.\n",*tablesize),*tablesize=16):0x0;
            break;
        case '?':
            printf("Missing argument to %c.", (char)optopt);
        default:
            return;
        }
    }
}

#endif
