// Copyright (c) Microsoft Corporation. All rights reserved.
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
#include <sys/mount.h>
#include <time.h>
#include "libc_t.h"
#include "mtest.h"

int t_status = 0;

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
    OE_TEST(oe_load_module_host_file_system() == OE_OK);
    OE_TEST(oe_load_module_host_socket_interface() == OE_OK);
    OE_TEST(oe_load_module_host_resolver() == OE_OK);
    OE_TEST(oe_load_module_host_resolver() == OE_OK);

    if (mount("/", "/", OE_HOST_FILE_SYSTEM, 0, NULL) != 0)
    {
        fprintf(stderr, "mount() failed\n");
        exit(1);
    }

    return run_tests();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    4096, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
