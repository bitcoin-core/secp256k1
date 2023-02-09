/***********************************************************************
 * Copyright (c) 2023 Jonas Nick                                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_CLI_UTIL_H
#define SECP256K1_CLI_UTIL_H

#include <string.h>

static int have_flag(int argc, char** argv, char *flag) {
    char** argm = argv + argc;
    argv++;
    while (argv != argm) {
        if (strcmp(*argv, flag) == 0) {
            return 1;
        }
        argv++;
    }
    return 0;
}

#endif /* SECP256K1_CLI_UTIL_H */
