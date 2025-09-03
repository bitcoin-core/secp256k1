/***********************************************************************
 * Copyright (c) 2025  Matias Furszyfer (furszy)                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(SUPPORTS_CONCURRENCY) && SUPPORTS_CONCURRENCY
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "unit_test.h"
#include "testrand.h"
#include "tests_common.h"

/* Number of times certain tests will run */
int COUNT = 16;

static int parse_jobs_count(const char* key, const char* value, struct Args* out);
static int parse_iterations(const char* arg);

/*
 *   Main entry point for handling command-line arguments.
 *
 *   This function is responsible for parsing a single key/value pair
 *   (e.g., -jobs=4) and updating the provided Args struct accordingly.
 *
 *   Developers should extend this function whenever new command-line
 *   options are introduced. Each new argument should be validated,
 *   converted to the appropriate type, and stored in the 'Args' struct.
 */
static int parse_arg(const char* key, const char* value, struct TestFramework* tf) {
    /* Number of concurrent tasks */
    if (strcmp(key, "j") == 0 || strcmp(key, "jobs") == 0) {
        return parse_jobs_count(key, value, &tf->args);
    }
    /* Number of iterations */
    if (strcmp(key, "iter") == 0 || strcmp(key, "iterations") == 0) {
        return parse_iterations(value);
    }
    /* Custom seed */
    if (strcmp(key, "seed") == 0) {
        tf->args.custom_seed = (!value || strcmp(value, "NULL") == 0) ? NULL : value;
        return 0;
    }

    /* Unknown key: report just so typos don’t silently pass. */
    printf("Unknown argument '-%s=%s'\n", key, value);
    return 0;
}

/* Main entry point for reading environment variables */
static int read_env(void) {
    const char* env_iter = getenv("SECP256K1_TEST_ITERS");
    if (env_iter && strlen(env_iter) > 0) {
        return parse_iterations(env_iter);
    }
    return 0;
}

static int parse_jobs_count(const char* key, const char* value, struct Args* out) {
    char* ptr_val;
    long val = strtol(value, &ptr_val, 10); /* base 10 */
    if (*ptr_val != '\0') {
        fprintf(stderr, "Invalid number for -%s=%s\n", key, value);
        return -1;
    }
    if (val < 0 || val > MAX_SUBPROCESSES) {
        fprintf(stderr, "Arg '-%s' out of range: '%ld'. Range: 0..%d\n", key, val, MAX_SUBPROCESSES);
        return -1;
    }
    out->num_processes = (int) val;
    return 0;
}

static int parse_iterations(const char* arg) {
    if (!arg) return 0;
    COUNT = (int) strtol(arg, NULL, 0);
    if (COUNT <= 0) {
        fputs("An iteration count of 0 or less is not allowed.\n", stderr);
        return -1;
    }
    printf("Iterations count = %i\n", COUNT);
    return 0;
}

/* Read args; all must be "-key=value" */
static int read_args(int argc, char** argv, int start, struct TestFramework* tf) {
    int i;
    char* eq;
    for (i = start; i < argc; i++) {
        const char* arg = argv[i];
        if (!arg || arg[0] != '-') {
            fprintf(stderr, "Arg '%s' must start with '-'\n", arg ? arg : "(null)");
            return -1;
        }

        eq = strchr(arg, '=');
        if (eq == NULL || eq == arg+1) {
            fprintf(stderr, "Arg %s must be -key=value\n", arg);
            return -1;
        }

        *eq = '\0';
        if (parse_arg(arg + 1, eq + 1, tf) != 0) {
            return -1;
        }
    }
    return 0;
}

static void run_test(const struct TestEntry* t) {
    printf("Running %s..\n", t->name);
    t->func();
    printf("%s PASSED\n", t->name);
}

/* Process tests in sequential order */
static int run_sequential(struct TestFramework* tf) {
    TestRef ref;
    struct TestModule* mdl;
    for (ref.group = 0; ref.group < tf->num_modules; ref.group++) {
        mdl = &tf->registry_modules[ref.group];
        for (ref.idx = 0; ref.idx < mdl->size; ref.idx++) {
            run_test(&mdl->data[ref.idx]);
        }
    }
    return EXIT_SUCCESS;
}

#if SUPPORTS_CONCURRENCY
/* Process tests in parallel */
static int run_concurrent(struct TestFramework* tf) {
    /* Sub-processes info */
    pid_t workers[MAX_SUBPROCESSES];
    int pipes[MAX_SUBPROCESSES][2];
    /* Next worker to send work */
    int worker_idx;
    /* Parent process exit status */
    int status = EXIT_SUCCESS;
    /* Loop iterator */
    int it;
    /* Loop ref */
    TestRef ref;
    /* Launch worker processes */
    for (it = 0; it < tf->args.num_processes; it++) {
        pid_t pid;
        if (pipe(pipes[it]) != 0) {
            perror("Error during pipe setup");
            return EXIT_FAILURE;
        }

        pid = fork();
        if (pid < 0) {
            perror("Error during process fork");
            return EXIT_FAILURE;
        }

        if (pid == 0) {
            /* Child worker: run tests assigned via pipe */
            close(pipes[it][1]); /* Close write end */
            while (read(pipes[it][0], &ref, sizeof(ref)) == sizeof(ref)) {
                run_test(&tf->registry_modules[ref.group].data[ref.idx]);
            }
            _exit(EXIT_SUCCESS); /* finish child process */
        } else {
            /* Parent: save worker pid */
            close(pipes[it][0]); /* Close read end */
            workers[it] = pid;
        }
    }

    /* Now that we have all sub-processes, distribute workload in round-robin */
    worker_idx = 0;
    for (ref.group = 0; ref.group < tf->num_modules; ref.group++) {
        struct TestModule* mdl = &tf->registry_modules[ref.group];
        for (ref.idx = 0; ref.idx < mdl->size; ref.idx++) {
            if (write(pipes[worker_idx][1], &ref, sizeof(ref)) == -1) {
                perror("Error during workload distribution");
                return EXIT_FAILURE;
            }
            if (++worker_idx >= tf->args.num_processes) worker_idx = 0;
        }
    }

    /* Close all pipes to signal workers to exit */
    for (it = 0; it < tf->args.num_processes; it++) close(pipes[it][1]);
    /* Wait for all workers */
    for (it = 0; it < tf->args.num_processes; it++) {
        int ret = 0;
        if (waitpid(workers[it], &ret, 0) == -1 || ret != 0) {
            status = EXIT_FAILURE;
        }
    }

    return status;
}
#endif

static int tf_init(struct TestFramework* tf, int argc, char** argv)
{
    /* Caller must set tf->registry and tf->num_tests before calling tf_init. */
    if (tf->registry_modules == NULL || tf->num_modules <= 0) {
        fprintf(stderr, "Error: tests registry not provided or empty\n");
        return EXIT_FAILURE;
    }

    /* Initialize command-line options */
    tf->args.num_processes = 0;
    tf->args.custom_seed = NULL;

    /* Disable buffering for stdout to improve reliability of getting
     * diagnostic information. Happens right at the start of main because
     * setbuf must be used before any other operation on the stream. */
    setbuf(stdout, NULL);
    /* Also disable buffering for stderr because it's not guaranteed that it's
     * unbuffered on all systems. */
    setbuf(stderr, NULL);

    /* Parse env args */
    if (read_env() != 0) return EXIT_FAILURE;

    /* Parse command-line args */
    if (argc > 1) {
        int named_arg_start = 1; /* index to begin processing named arguments */
        if (argc - 1 > MAX_ARGS) { /* first arg is always the binary path */
            fprintf(stderr, "Too many command-line arguments (max: %d)\n", MAX_ARGS);
            return EXIT_FAILURE;
        }

        /* Compatibility Note: The first two args were the number of iterations and the seed. */
        /* If provided, parse them and adjust the starting index for named arguments accordingly. */
        if (argv[1] && argv[1][0] != '-') {
            int has_seed = argc > 2 && argv[2] && argv[2][0] != '-';
            if (parse_iterations(argv[1]) != 0) return EXIT_FAILURE;
            if (has_seed) tf->args.custom_seed = (strcmp(argv[2], "NULL") == 0) ? NULL : argv[2];
            named_arg_start = has_seed ? 3 : 2;
        }
        if (read_args(argc, argv, named_arg_start, tf) != 0) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

static int tf_run(struct TestFramework* tf) {
    /* Process exit status */
    int status;
    /* Loop iterator */
    int it;
    /* Initial test time */
    int64_t start_time = gettime_i64(); /* maybe move this after the slots set */

    /* Run test RNG tests (must run before we really initialize the test RNG) */
    /* Note: currently, these tests are executed sequentially because there */
    /* is really only one test. */
    for (it = 0; tf->registry_no_rng && it < tf->registry_no_rng->size; it++) {
        run_test(&tf->registry_no_rng->data[it]);
    }

    /* Initialize test RNG and library contexts */
    testrand_init(tf->args.custom_seed);
    if (tf->fn_setup && tf->fn_setup() != 0) return EXIT_FAILURE;

    /* Check whether to process tests sequentially or concurrently */
    if (tf->args.num_processes <= 1) {
        status = run_sequential(tf);
    } else {
#if SUPPORTS_CONCURRENCY
        status = run_concurrent(tf);
#else
        fputs("Parallel execution not supported on your system. Running sequentially..\n", stderr);
        status = run_sequential(tf);
#endif
    }

    /* Print accumulated time */
    printf("Total execution time: %.3f seconds\n", (double)(gettime_i64() - start_time) / 1000000);
    if (tf->fn_teardown && tf->fn_teardown() != 0) return EXIT_FAILURE;

    return status;
}
