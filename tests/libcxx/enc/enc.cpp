#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <stdio.h>
#include <openenclave/enclave.h>
#include <openenclave/bits/calls.h>
#include "../host/ocalls.h"
#include "../host/args.h"

extern const char* __test__;

extern "C" int main(int argc, const char* argv[]);

extern "C" void _exit(int status)
{
    OE_OCall(OCALL_EXIT, status, NULL, 0);
    abort();
}

extern "C" void _Exit(int status)
{
    _exit(status);
    abort();
}

extern "C" void exit(int status)
{
    _exit(status);
    abort();
}

typedef void (*Handler)(int signal);

Handler signal(int signal, Handler)
{
    /* Ignore! */
    return NULL;
}

extern "C" int close(int fd)
{
    assert("close() panic" == NULL);
    return 0;
}

OE_ECALL void Test(Args* args)
{
    extern const char* __TEST__NAME;
    if (args)
    {
        printf("RUNNING: %s\n", __TEST__NAME);
        static const char* argv[] = { "test", NULL, };
        static int argc = sizeof(argv) / sizeof(argv[0]);
        args->ret = main(argc, argv);
        args->test = OE_HostStrdup(__TEST__NAME);
    }
}
