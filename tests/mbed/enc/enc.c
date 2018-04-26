// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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

OE_ECALL void Test(Args* args)
{
    if (args)
    {
        printf("RUNNING: %s\n", __TEST__);
        /* verbose option is enabled as some of the functionality in
           helper.function
               such as redirect output, restore output is trying to assign
           values to stdout
               which inturn causes seg fault. to avoid this we enabled verbose
           options
           such that those function calls will be suppressed */
        static const char* argv[] = {"test", "-v", "NULL"};
        static int argc = sizeof(argv) / sizeof(argv[0]);
        printf("\n before main %d\n", argc);
        argv[2] = args->test;
        args->ret = main(argc, argv);
        printf("\n in main\n");
        args->test = OE_HostStrdup(__TEST__);
    }
}
