/***********************************************************************
 * Copyright (c) 2025  Matias Furszyfer (furszy)                       *
 * Distributed under the MIT software license, see the accompanying    *
 * file COPYING or https://www.opensource.org/licenses/mit-license.php.*
 ***********************************************************************/

#ifndef SECP256K1_UNIT_TEST_H
#define SECP256K1_UNIT_TEST_H

/* --------------------------------------------------------- */
/* Configurable constants                                    */
/* --------------------------------------------------------- */

/* Maximum number of command-line arguments.
 * Must be at least as large as the total number of tests
 * to allow specifying all tests individually. */
#define MAX_ARGS 150
/* Maximum number of parallel jobs */
#define MAX_SUBPROCESSES 16

/* --------------------------------------------------------- */
/* Test Framework Registry Macros                            */
/* --------------------------------------------------------- */

#define CASE(name) { #name, run_##name }
#define CASE1(name) { #name, name }

#define MAKE_TEST_MODULE(name) {\
    #name, \
    tests_##name, \
    sizeof(tests_##name) / sizeof(tests_##name[0]) \
}

/* Macro to wrap a test internal function with a COUNT loop (iterations number) */
#define REPEAT_TEST(fn) REPEAT_TEST_MULT(fn, 1)
#define REPEAT_TEST_MULT(fn, multiplier)            \
    static void fn(void) {                          \
        int i;                                      \
        int repeat = COUNT * (multiplier);          \
        for (i = 0; i < repeat; i++)                \
            fn##_internal();                        \
    }



/* --------------------------------------------------------- */
/* Test Framework API                                        */
/* --------------------------------------------------------- */

typedef void (*test_fn)(void);

struct TestEntry {
    const char* name;
    test_fn func;
};

struct TestModule {
    const char* name;
    struct TestEntry* data;
    int size;
};

typedef int (*setup_ctx_fn)(void);
typedef int (*teardown_fn)(void);

/* Reference to a test in the registry. Group index and test index */
typedef struct {
    int group;
    int idx;
} TestRef;

/* --- Command-line args --- */
struct Args {
    /* 0 => sequential; 1..MAX_SUBPROCESSES => parallel workers */
    int num_processes;
    /* Specific RNG seed */
    const char* custom_seed;
};

struct TestFramework {
    /* Command-line args */
    struct Args args;
    /* Test modules registry */
    const struct TestModule* registry_modules;
    /* Num of modules */
    int num_modules;
    /* Registry for tests that require no RNG init */
    const struct TestModule* registry_no_rng;
    /* Specific context setup and teardown functions */
    setup_ctx_fn fn_setup;
    teardown_fn fn_teardown;
};

/* --------------------------------------------------------- */
/* Public API                                                */
/* --------------------------------------------------------- */

/*
 * Initialize the test framework.
 *
 * Must be called before tf_run() and as early as possible in the program.
 * Parses command-line arguments and configures the framework context.
 * The caller must set 'registry_modules' and 'num_modules' before calling.
 *
 * Returns:
 *   EXIT_SUCCESS (0) on success,
 *   EXIT_FAILURE (non-zero) on error.
 */
static int tf_init(struct TestFramework* tf, int argc, char** argv);

/*
 * Run tests based on the provided test framework context.
 *
 * This function uses the configuration stored in the TestFramework
 * (targets, number of processes, iteration count, etc.) to determine
 * which tests to execute and how to execute them.
 *
 * Returns:
 *   EXIT_SUCCESS (0) if all tests passed,
 *   EXIT_FAILURE (non-zero) otherwise.
 */
static int tf_run(struct TestFramework* tf);

#endif /* SECP256K1_UNIT_TEST_H */
