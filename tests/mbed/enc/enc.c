// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <assert.h>
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

OE_ECALL void Test(Args* args)
{
    if (args)
    {
        printf("RUNNING: %s\n", __TEST__);

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
