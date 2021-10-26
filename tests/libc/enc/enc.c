// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/constants_x64.h>
#include <openenclave/internal/libc/init.h>
#include <openenclave/internal/tests.h>
#include <search.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/mount.h>
#include <time.h>
#include "libc_t.h"
#include "mtest.h"

#include "libc_tests.h"

#pragma STDC FENV_ACCESS ON

#if defined(__x86_64__) || defined(_M_X64)
#define XMM_OK
#endif

#if defined(XMM_OK)
void _reset_fxsave_state()
{
    /* Initialize the FXSAVE state values to Linux x86-64 ABI defined values:
     * FCW = 0x037F, MXCSR = 0x1F80, MXCSR mask = 0xFFFF */
    static OE_ALIGNED(OE_FXSAVE_ALIGNMENT) const uint64_t
        _initial_fxstate[OE_FXSAVE_AREA_SIZE / sizeof(uint64_t)] = {
            0x037F, 0, 0, 0xFFFF00001F80,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
            0,      0, 0, 0,
        };

    asm volatile("fxrstor %[fx_state] \n\t"
                 :
                 : [fx_state] "m"(_initial_fxstate)
                 :);
}
#endif

int t_status = 0;

int device_init()
{
    OE_TEST(oe_load_module_host_file_system() == OE_OK);
    OE_TEST(oe_load_module_host_socket_interface() == OE_OK);
    // OE_TEST(oe_load_module_host_epoll() == OE_OK);

#ifndef CODE_COVERAGE
    OE_TEST(mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) == 0);
#endif
    return 0;
}

int t_printf(const char* s, ...)
{
    va_list ap;
    char buf[512];

    t_status = 1;
    va_start(ap, s);
    int n = vsnprintf(buf, sizeof buf, s, ap);
    va_end(ap);

    printf("%s\n", buf);
    return n;
}

int t_setrlim(int r, int64_t lim)
{
    return 0;
}

int run_test_helper(const char* test_name, libc_test_function_t test_function)
{
    extern char** __environ;
    char** environ = NULL;
    int ret = 1;

    /* Print running message. */
    printf("=== running: %s\n", test_name);

#if defined(XMM_OK)
    /* Reset the FXSAVE state between tests.
     * The original libc tests for floating point math were compiled as
     * individual executables and assume ABI-initialized floating point and
     * MXCSR state. Since the enclave runs multiple tests in the same enclave
     * consecutively, we reset the FXSAVE state on each run. */
    _reset_fxsave_state();
#endif

    /* Disable Open Enclave debug malloc checks. */
    extern bool oe_disable_debug_malloc_check;
    oe_disable_debug_malloc_check = true;

    /* Allocate an environment for invoking the test. */
    if (!(environ = (char**)calloc(1, sizeof(char*))))
        goto done;

    memset(environ, 0, sizeof(char**));
    __environ = environ;

    /* Run the test */
    const char* argv[] = {"test", NULL};

    if (test_function(1, argv) != 0)
    {
        /* Prevent cascading of false negatives. */
        t_status = 0;

        fprintf(stderr, "*** failed: %s\n", test_name);
        goto done;
    }

    ret = 0;

done:

    free(environ);
    __environ = NULL;

    return ret;
}

int run_test(const char* test_name)
{
    device_init();
    libc_test_function_t test = get_test_case(test_name);

    OE_TEST(oe_test_libc_is_initialized());

    if (test)
    {
        return run_test_helper(test_name, test);
    }

    printf("*** failed: test %s is not a valid test", test_name);
    return 1;
}

int run_all_tests()
{
    int ret;

    device_init();

    OE_TEST(oe_test_libc_is_initialized());

    ret = 0;
    for (int i = 0; i < sizeof(libc_tests) / sizeof(libc_test_entry_t); i++)
    {
        libc_test_entry_t test = libc_tests[i];
        ret += run_test_helper(test.test_name, test.test_function);
    }

    return ret;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    512,  /* NumHeapPages */
    256,  /* NumStackPages */
    4);   /* NumTCS */

#define TA_UUID                                            \
    { /* d7fe296a-24e9-46d1-aa78-9c7395082a41 */           \
        0xd7fe296a, 0x24e9, 0x46d1,                        \
        {                                                  \
            0xaa, 0x78, 0x9c, 0x73, 0x95, 0x08, 0x2a, 0x41 \
        }                                                  \
    }

OE_SET_ENCLAVE_OPTEE(
    TA_UUID,
    1 * 1024 * 1024,
    12 * 1024,
    0,
    "1.0.0",
    "libc test")
