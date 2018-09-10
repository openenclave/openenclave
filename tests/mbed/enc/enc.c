// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/syscall.h>
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <unistd.h>
#include "../host/args.h"

int main(int argc, const char* argv[]);

void _exit(int status)
{
    oe_call_host("ocall_exit", (void*)(long)status);
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

static oe_result_t _syscall_hook(
    long number,
    long arg1,
    long arg2,
    long arg3,
    long arg4,
    long arg5,
    long arg6,
    long* ret)
{
    oe_result_t result = OE_UNEXPECTED;

    if (ret)
        *ret = -1;

    if (!ret)
        OE_RAISE(OE_INVALID_PARAMETER);

    switch (number)
    {
        case SYS_open:
        {
            const int flags = (const int)arg2;

            /* If attempting to open any file for read-only */
            if (flags == O_RDONLY)
            {
                *ret = STDIN_FILENO;
                OE_RAISE(OE_OK);
            }

            break;
        }
    }

    OE_RAISE(OE_UNSUPPORTED);

done:
    return result;
}

OE_ECALL void Test(Args* args)
{
    if (args)
    {
        printf("RUNNING: %s\n", __TEST__);

        // Install a syscall hook to handle special behavior for mbed TLS.
        oe_register_syscall_hook(_syscall_hook);

        // verbose option is enabled as some of the functionality in
        // helper.function such as redirect output, restore output is trying
        // to assign values to stdout which in turn causes segmentation fault.
        // To avoid this we enabled verbose options such that those function
        // calls will be suppressed.

        static const char* argv[] = {"test", "-v", "NULL"};
        static int argc = sizeof(argv) / sizeof(argv[0]);
        printf("\n before main %d\n", argc);
        argv[2] = args->test;
        args->ret = main(argc, argv);
        printf("\n in main\n");
        args->test = oe_host_strndup(__TEST__, OE_SIZE_MAX);
    }
}

/*
**==============================================================================
**
** oe_handle_verify_report():
**
**     Since liboeenclave is not linked, we must define a version of this
**     function here (since liboecore depends on it). This version asserts
**     and aborts().
**
**==============================================================================
*/

void oe_handle_verify_report(uint64_t argIn, uint64_t* argOut)
{
    assert("oe_handle_verify_report()" == NULL);
    abort();
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* AllowDebug */
    1024, /* HeapPageCount */
    1024, /* StackPageCount */
    2);   /* TCSCount */
