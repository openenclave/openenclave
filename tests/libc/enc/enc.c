#include <assert.h>
#include <errno.h>
#include <openenclave/bits/calls.h>
#include <openenclave/enclave.h>
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
    OE_OCall(OCALL_EXIT, status, NULL, 0);
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

int t_setrlim(int r, long lim)
{
    return 0;
}

extern char** __environ;

extern const char* __test__;

OE_ECALL void Test(Args* args)
{
    if (args)
    {
        printf("RUNNING: %s\n", __TEST__);

        if (!(__environ = (char**)calloc(1, sizeof(char**))))
            args->ret = 1;

        static const char* argv[] = {
            "test", NULL,
        };
        args->ret = main(1, argv);
        args->test = OE_HostStrdup(__TEST__);
    }
}
