#include <stdlib.h>
#include <assert.h>
#include <signal.h>
#include <openenclave/enclave.h>
#include "../../runtest/ocalls.h"
#include "../../runtest/args.h"

extern const char* __test__;

extern "C" int main(int argc, const char* argv[]);

extern "C" void _exit(int status)
{
    OE_OCall(OCALL_EXIT, status, NULL);
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

OE_ECALL void Test(Args* args)
{
    if (args)
    {
        static const char* argv[] = { "test", NULL, };
        static int argc = sizeof(argv) / sizeof(argv[0]);
        args->ret = main(argc, argv);
        args->test = OE_HostStrdup(__test__);
    }
}
