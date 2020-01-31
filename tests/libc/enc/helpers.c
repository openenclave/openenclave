// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "helpers.h"

#include <dirent.h>
#include <errno.h>
#include <libgen.h>
#include <openenclave/enclave.h>
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
#include "mtest.h"

extern char** __environ;

#pragma STDC FENV_ACCESS ON

#if defined(__x86_64__) || defined(_M_X64)
#define XMM_OK
#endif

#if defined(XMM_OK)
/* Type of the control word.  */
typedef unsigned int fpu_control_t __attribute__((__mode__(__HI__)));
/* Macros for accessing the hardware control word.  */
#define _FPU_GETCW(cw) __asm__ __volatile__("fnstcw %0" : "=m"(*&cw))
#define _FPU_SETCW(cw) __asm__ __volatile__("fldcw %0" : : "m"(*&cw))
#endif

// Space for global libc environment
static char** environ = NULL;
int t_status = 0;

int device_init()
{
    OE_TEST(oe_load_module_host_file_system() == OE_OK);
    OE_TEST(oe_load_module_host_socket_interface() == OE_OK);
    // OE_TEST(oe_load_module_host_epoll() == OE_OK);

    OE_TEST(mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) == 0);

    return 0;
}

#if defined(XMM_OK)
int my_printfpu_control()
{
    fpu_control_t cw;
    _FPU_GETCW(cw);
    return cw;
}

uint32_t my_getmxcsr()
{
    uint32_t csr;
    asm volatile("stmxcsr %0" : "=m"(csr));
    return csr;
}

void my_setmxcsr(uint32_t csr)
{
    asm volatile("ldmxcsr %0" : : "m"(csr));
}
#endif

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

bool test_setup()
{
    extern bool oe_disable_debug_malloc_check;
    static bool _devices_initialized = false;

    // Only initialize devices once
    if (!_devices_initialized)
    {
        device_init();
        _devices_initialized = true;
    }

    /* Disable Open Enclave debug malloc checks. */
    oe_disable_debug_malloc_check = true;

#if defined(XMM_OK)
    /* Verify that the FPU control word and SSE control/status flags are set
     * correctly before each test */
    uint32_t cw = my_printfpu_control();
    OE_TEST(cw == 0x37f);

    uint32_t csr = my_getmxcsr();
    OE_TEST(csr == 0x1f80);
#endif

    /* Allocate an environment for invoking the test. */
    if (!(environ = (char**)calloc(1, sizeof(char*))))
        return false;

    memset(environ, 0, sizeof(char**));
    __environ = environ;

    return true;
}

void test_teardown()
{
    if (environ)
        free(environ);
    __environ = NULL;
    environ = NULL;
}

int run_single_test(const char* test_name, libc_test_function_t test_function)
{
    int ret = 1;
    static const char* argv[] = {"test", NULL};
    static const int argc = 1;

    printf("=== RUNNING: %s\n", test_name);

    if (!test_setup())
    {
        printf("*** failed test_setup\n");
        goto done;
    }

    /* Run test */
    if (test_function(argc, argv) != 0)
    {
        t_status = 0;

        fprintf(stderr, "*** failed: %s\n", test_name);
        goto done;
    }

    ret = 0;

done:
    test_teardown();
    return ret;
}
