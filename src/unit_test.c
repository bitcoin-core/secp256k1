/***********************************************************************
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#if defined(SUPPORTS_CONCURRENCY)
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>
#endif

#include "unit_test.h"
#include "testrand.h"
#include "tests_common.h"

#define UNUSED(x) (void)(x)

/* Number of times certain tests will run */
int COUNT = 16;

static int parse_jobs_count(const char* key, const char* value, struct tf_framework* tf);
static int parse_iterations(const char* key, const char* value, struct tf_framework* tf);
static int parse_seed(const char* key, const char* value, struct tf_framework* tf);

/* Mapping table: key -> handler */
typedef int (*ArgHandler)(const char* key, const char* value, struct tf_framework* tf);
struct ArgMap {
    const char* key;
    ArgHandler handler;
};

/*
 *   Main entry point for handling command-line arguments.
 *
 *   Developers should extend this map whenever new command-line
 *   options are introduced. Each new argument should be validated,
 *   converted to the appropriate type, and stored in 'tf->args' struct.
 */
static struct ArgMap arg_map[] = {
    { "j", parse_jobs_count }, { "jobs", parse_jobs_count },
    { "i", parse_iterations }, { "iterations", parse_iterations },
    { "seed", parse_seed },
    { NULL, NULL } /* sentinel */
};

/* Display options that are not printed elsewhere */
static void print_args(const struct tf_args* args) {
    printf("iterations = %d\n", COUNT);
    printf("jobs = %d. %s execution.\n", args->num_processes, args->num_processes > 1 ? "Parallel" : "Sequential");
}

/* Main entry point for reading environment variables */
static int read_env(struct tf_framework* tf) {
    const char* env_iter = getenv("SECP256K1_TEST_ITERS");
    if (env_iter && strlen(env_iter) > 0) {
        return parse_iterations("i", env_iter, tf);
    }
    return 0;
}

static int parse_arg(const char* key, const char* value, struct tf_framework* tf) {
    int i;
    for (i = 0; arg_map[i].key != NULL; i++) {
        if (strcmp(key, arg_map[i].key) == 0) {
            return arg_map[i].handler(key, value, tf);
        }
    }
    /* Unknown key: report just so typos don't silently pass. */
    fprintf(stderr, "Unknown argument '-%s=%s'\n", key, value);
    return -1;
}

static int parse_jobs_count(const char* key, const char* value, struct tf_framework* tf) {
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
    tf->args.num_processes = (int) val;
    return 0;
}

static int parse_iterations(const char* key, const char* value, struct tf_framework* tf) {
    UNUSED(key); UNUSED(tf);
    if (!value) return 0;
    COUNT = (int) strtol(value, NULL, 0);
    if (COUNT <= 0) {
        fputs("An iteration count of 0 or less is not allowed.\n", stderr);
        return -1;
    }
    return 0;
}

static int parse_seed(const char* key, const char* value, struct tf_framework* tf) {
    UNUSED(key);
    tf->args.custom_seed = (!value || strcmp(value, "NULL") == 0) ? NULL : value;
    return 0;
}

/* Strip up to two leading dashes */
static const char* normalize_key(const char* arg, const char** err_msg) {
    const char* key;
    if (!arg || arg[0] != '-') {
        *err_msg = "missing initial dash";
        return NULL;
    }
    /* single-dash short option */
    if (arg[1] != '-') return arg + 1;

    /* double-dash checks now */
    if (arg[2] == '\0') {
        *err_msg = "missing option name after double dash";
        return NULL;
    }

    if (arg[2] == '-') {
        *err_msg = "too many leading dashes";
        return NULL;
    }

    key = arg + 2;
    if (key[1] == '\0') {
        *err_msg = "short option cannot use double dash";
        return NULL;
    }
    return key;
}

/* Read args: all must be in the form -key=value, --key=value or -key=value */
static int read_args(int argc, char** argv, int start, struct tf_framework* tf) {
    int i;
    const char* key;
    const char* value;
    char* eq;
    const char* err_msg = "unknown error";
    for (i = start; i < argc; i++) {
        char* raw_arg = argv[i];
        if (!raw_arg || raw_arg[0] != '-') {
            fprintf(stderr, "Invalid arg '%s': must start with '-'\n", raw_arg ? raw_arg : "(null)");
            return -1;
        }

        key = normalize_key(raw_arg, &err_msg);
        if (!key || *key == '\0') {
            fprintf(stderr, "Invalid arg '%s': %s. Must be -k=value or --key=value\n", raw_arg, err_msg);
            return -1;
        }

        eq = strchr(raw_arg, '=');
        if (!eq || eq == raw_arg + 1) {
            fprintf(stderr, "Invalid arg '%s': must be -k=value or --key=value\n", raw_arg);
            return -1;
        }

        *eq = '\0'; /* split key and value */
        value = eq + 1;
        if (!value || *value == '\0') { /* value is empty */
            fprintf(stderr, "Invalid arg '%s': value cannot be empty\n", raw_arg);
            return -1;
        }

        if (parse_arg(key, value, tf) != 0) return -1;
    }
    return 0;
}

static void run_test(const struct tf_test_entry* t) {
    printf("Running %s..\n", t->name);
    t->func();
    printf("%s PASSED\n", t->name);
}

/* Process tests in sequential order */
static int run_sequential(struct tf_framework* tf) {
    tf_test_ref ref;
    const struct tf_test_module* mdl;
    for (ref.group = 0; ref.group < tf->num_modules; ref.group++) {
        mdl = &tf->registry_modules[ref.group];
        for (ref.idx = 0; ref.idx < mdl->size; ref.idx++) {
            run_test(&mdl->data[ref.idx]);
        }
    }
    return EXIT_SUCCESS;
}

#if defined(SUPPORTS_CONCURRENCY)
/* Process tests in parallel */
static int run_concurrent(struct tf_framework* tf) {
    /* Sub-processes info */
    pid_t workers[MAX_SUBPROCESSES];
    int pipefd[2];
    int status = EXIT_SUCCESS;
    int it; /* loop iterator */
    tf_test_ref ref; /* test index */

    if (pipe(pipefd) != 0) {
        perror("Error during pipe setup");
        return EXIT_FAILURE;
    }

    /* Launch worker processes */
    for (it = 0; it < tf->args.num_processes; it++) {
        pid_t pid = fork();
        if (pid < 0) {
            perror("Error during process fork");
            return EXIT_FAILURE;
        }
        if (pid == 0) {
            /* Child worker: read jobs from the shared pipe */
            close(pipefd[1]); /* children never write */
            while (read(pipefd[0], &ref, sizeof(ref)) == sizeof(ref)) {
                run_test(&tf->registry_modules[ref.group].data[ref.idx]);
            }
            _exit(EXIT_SUCCESS); /* finish child process */
        } else {
            /* Parent: save worker pid */
            workers[it] = pid;
        }
    }

    /* Parent: write all tasks into the pipe */
    close(pipefd[0]); /* close read end */
    for (ref.group = 0; ref.group < tf->num_modules; ref.group++) {
        const struct tf_test_module* mdl = &tf->registry_modules[ref.group];
        for (ref.idx = 0; ref.idx < mdl->size; ref.idx++) {
            if (write(pipefd[1], &ref, sizeof(ref)) == -1) {
                perror("Error during workload distribution");
                close(pipefd[1]);
                return EXIT_FAILURE;
            }
        }
    }
    /* Close write end to signal EOF */
    close(pipefd[1]);
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

static int tf_init(struct tf_framework* tf, int argc, char** argv)
{
    /* Caller must set the registry and its size before calling tf_init */
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
    if (read_env(tf) != 0) return EXIT_FAILURE;

    /* Parse command-line args */
    if (argc > 1) {
        int named_arg_start = 1; /* index to begin processing named arguments */
        if (argc - 1 > MAX_ARGS) { /* first arg is always the binary path */
            fprintf(stderr, "Too many command-line arguments (max: %d)\n", MAX_ARGS);
            return EXIT_FAILURE;
        }

        /* Compatibility Note: The first two args were the number of iterations and the seed. */
        /* If provided, parse them and adjust the starting index for named arguments accordingly. */
        if (argv[1][0] != '-') {
            int has_seed = argc > 2 && argv[2][0] != '-';
            if (parse_iterations("i", argv[1], tf) != 0) return EXIT_FAILURE;
            if (has_seed) parse_seed("seed", argv[2], tf);
            named_arg_start = has_seed ? 3 : 2;
        }
        if (read_args(argc, argv, named_arg_start, tf) != 0) {
            return EXIT_FAILURE;
        }
    }

    return EXIT_SUCCESS;
}

static int tf_run(struct tf_framework* tf) {
    /* Process exit status */
    int status;
    /* Loop iterator */
    int it;
    /* Initial test time */
    int64_t start_time = gettime_i64();

    /* Log configuration */
    print_args(&tf->args);

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
#if defined(SUPPORTS_CONCURRENCY)
        status = run_concurrent(tf);
#else
        fputs("Parallel execution not supported on your system. Running sequentially...\n", stderr);
        status = run_sequential(tf);
#endif
    }

    /* Print accumulated time */
    printf("Total execution time: %.3f seconds\n", (double)(gettime_i64() - start_time) / 1000000);
    if (tf->fn_teardown && tf->fn_teardown() != 0) return EXIT_FAILURE;

    return status;
}
