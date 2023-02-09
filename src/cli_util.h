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

/* takes an array containing the arguments that the user is allowed to enter on the command-line
   returns:
      - 1 if the user entered an invalid argument
      - 0 if all the user entered arguments are valid */
static int have_invalid_args(int argc, char** argv, char** valid_args, size_t n) {
    size_t i;
    int found_valid;
    char** argm = argv + argc;
    argv++;

    while (argv != argm) {
        found_valid = 0;
        for (i = 0; i < n; i++) {
            if (strcmp(*argv, valid_args[i]) == 0) {
                found_valid = 1; /* user entered a valid arg from the list */
                break;
            }
        }
        if (found_valid == 0) {
            return 1; /* invalid arg found */
        }
        argv++;
    }
    return 0;
}

#endif /* SECP256K1_CLI_UTIL_H */
