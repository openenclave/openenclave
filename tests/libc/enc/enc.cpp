// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include "../args.h"

#include <stdint.h>
#include <stdio.h>
#include <time.h>
#include <errno.h>
#include <dirent.h>
#include <string.h>
#include <stdlib.h>
#include <string.h>
#include <libgen.h>
#include <search.h>
#include <stdarg.h>
#include "mtest.h"
#include "tests.h"

int t_status = 0;

extern "C" int t_printf(const char* s, ...)
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

extern "C" int t_setrlim(int r, int64_t lim)
{
    return 0;
}

extern char** __environ;

extern bool oe_disable_debug_malloc_check;

static void _run_test(
    const char* name, 
    int (*func)(int argc, const char* argv[]), 
    args_t* args)
{
    printf("=== running: %s\n", name);

    oe_disable_debug_malloc_check = true;

    memset(__environ, 0, sizeof(char**));

    const char* argv[] = { "test", NULL };

    if (func(1, argv) != 0)
    {
        fprintf(stderr, "*** failed: %s\n", name);
        args->ret++;
    }
}

#define RUN_TEST(NAME) _run_test(#NAME, NAME, args)

OE_ECALL void Test(void* args_)
{
    args_t* args = (args_t*)args_;

    if (!(__environ = (char**)calloc(1, sizeof(char**))))
        args->ret = 1;

    args->ret = 0;

#include "tests.cpp"

    free(__environ);
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    4096, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
