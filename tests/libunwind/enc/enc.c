// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "libunwind_t.h"
#include "pid.h"

uint32_t g_pid;

int main(int argc, const char* argv[]);

void _exit(int status)
{
    exit_ocall(status);
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
    OE_UNUSED(r);
    OE_UNUSED(lim);
    return 0;
}

extern char** __environ;

extern const char* __test__;

int test(char test_name[201], uint32_t pid)
{
    int rval = 1;
    g_pid = pid;
    printf("RUNNING: %s\n", __TEST__);
    if (!(__environ = (char**)calloc(1, sizeof(char*))))
    {
        return rval;
    }

    static const char* argv[] = {
        "test",
        NULL,
    };
    rval = main(1, argv);
    strncpy(test_name, __TEST__, STRLEN_MAX);

    free(__environ);
    return rval;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
