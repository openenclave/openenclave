// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../host/args.h"
#include "../host/ocalls.h"

int main(int argc, const char* argv[]);

void _exit(int status)
{
    oe_call_host("ocall_exit", (void*)(uint64_t)status);
    abort();
}

void _Exit(int status)
{
    _exit(status);
    abort();
}

void exit(int status)
{
    _exit(status);
    abort();
}

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

extern char** __environ;

extern const char* __test__;

extern bool oe_disable_debug_malloc_check;

/* Return true if this test is on the leaky-test list. */
static bool _is_leaky_test(const char* test)
{
    static const char* _tests[] =
    {
    };

    for (size_t i = 0; i < OE_COUNTOF(_tests); i++)
    {
        if (strcmp(test, _tests[i]) == 0)
            return true;
    }

    return false;
}

OE_ECALL void Test(Args* args)
{
    if (args)
    {
        if (_is_leaky_test(__TEST__))
            oe_disable_debug_malloc_check = true;

        printf("RUNNING: %s\n", __TEST__);

        if (!(__environ = (char**)calloc(1, sizeof(char**))))
            args->ret = 1;

        static const char* argv[] = {
            "test", NULL,
        };

        args->ret = main(1, argv);
        args->test = oe_host_strndup(__TEST__, OE_SIZE_MAX);
        free(__environ);
    }
}
