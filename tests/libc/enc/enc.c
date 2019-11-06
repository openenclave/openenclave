// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

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
#include <time.h>
#include "libc_t.h"
#include "mtest.h"

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

int run_test(const char* name, int (*main)(int argc, const char* argv[]))
{
    extern char** __environ;
    char** environ = NULL;
    int ret = 1;

    /* Print running message. */
    printf("=== running: %s\n", name);

#if defined(XMM_OK)
    /* Verify that the FPU control word and SSE control/status flags are set
     * correctly before each test */
    uint32_t cw = my_printfpu_control();
    OE_TEST(cw == 0x37f);

    uint32_t csr = my_getmxcsr();
    OE_TEST(csr == 0x1f80);
#endif

    /* Disable Open Enclave debug malloc checks. */
    {
        extern bool oe_disable_debug_malloc_check;
        oe_disable_debug_malloc_check = true;
    }

    /* Allocate an environment for invoking the test. */
    {
        if (!(environ = (char**)calloc(1, sizeof(char**))))
            goto done;

        memset(environ, 0, sizeof(char**));
        __environ = environ;
    }

    /* Run the test */
    {
        const char* argv[] = {"test", NULL};

        if (main(1, argv) != 0)
        {
            /* Prevent cascading of false negatives. */
            t_status = 0;

            fprintf(stderr, "*** failed: %s\n", name);
            goto done;
        }
    }

    ret = 0;

done:

    free(environ);
    __environ = NULL;

    return ret;
}

extern int run_tests(void);

int test()
{
    device_init();
    return run_tests();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    512,  /* HeapPageCount */
    256,  /* StackPageCount */
    4);   /* TCSCount */

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
    TA_FLAG_EXEC_DDR,
    "1.0.0",
    "libc test")
