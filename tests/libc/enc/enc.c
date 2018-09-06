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

static const char* _leakey_tests[] = {
    "../../3rdparty/musl/libc-test/src/functional/env.c",
    "../../3rdparty/musl/libc-test/src/functional/search_insque.c",
    "../../3rdparty/musl/libc-test/src/regression/fgets-eof.c",
    "../../3rdparty/musl/libc-test/src/regression/putenv-doublefree.c",
    "../../3rdparty/musl/libc-test/src/regression/regex-backref-0.c",
    "../../3rdparty/musl/libc-test/src/regression/regex-bracket-icase.c",
    "../../3rdparty/musl/libc-test/src/regression/regexec-nosub.c",
    "../../3rdparty/musl/libc-test/src/regression/regex-ere-backref.c",
    "../../3rdparty/musl/libc-test/src/regression/regex-escaped-high-byte.c",
    "../../3rdparty/musl/libc-test/src/regression/regex-negated-range.c",
    "../../3rdparty/musl/libc-test/src/functional/time.c",
};

/* Return true if this test is known to leak memory. */
static bool _is_leaky_test(const char* test)
{
    for (size_t i = 0; i < OE_COUNTOF(_leakey_tests); i++)
    {
        if (strcmp(test, _leakey_tests[i]) == 0)
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

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    4096, /* HeapPageCount */
    1024, /* StackPageCount */
    8);   /* TCSCount */
