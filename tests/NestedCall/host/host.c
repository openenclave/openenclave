// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <limits.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../args.h"

OE_Enclave* enclave = NULL;

OE_OCALL void HostNestCalls(void* args_)
{
    OE_Result result;
    Args* args = (Args*)args_;

    printf("host: HostNestCalls depth [%d] started!\n", args->depth);

    if (args->in && !(args->out = strdup(args->in)))
    {
        args->ret = -1;
        return;
    }

    if (args->depth <= 0)
    {
        printf("host: HostNestCalls depth [%d] returned!.\n", args->depth);
        args->ret = 0;
        return;
    }

    /* Call into EnclaveNestCalls() function in the enclave */
    Args newArgs;
    memset(&newArgs, 0, sizeof(newArgs));
    newArgs.ret = -1;
    newArgs.depth = args->depth - 1;
    newArgs.testEh = args->testEh;
    char str[256];
    sprintf(str, "Nested call depth [%d].", newArgs.depth);

    if (!(newArgs.in = strdup(str)))
    {
        fprintf(stderr, "strdup() failed");
        exit(1);
    }

    if ((result = OE_CallEnclave(enclave, "EnclaveNestCalls", &newArgs)) !=
        OE_OK)
    {
        fprintf(stderr, "OE_CallEnclave() failed: result=%u", result);
        exit(1);
    }

    if (newArgs.ret != 0)
    {
        fprintf(stderr, "ECALL failed newArgs.result=%d", newArgs.ret);
        exit(1);
    }

    if (newArgs.in)
    {
        free((char*)newArgs.in);
        newArgs.in = NULL;
    }

    if (newArgs.out)
    {
        free((char*)newArgs.out);
        newArgs.out = NULL;
    }

    args->ret = 0;

    printf("host: HostNestCalls depth [%d] returned!.\n", args->depth);
    return;
}

void TestNestedCalls(int testEh, int depth)
{
    // OE_Result result;
    Args args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;
    args.testEh = testEh;
    args.depth = depth;
    args.in = "";
    args.out = "";

    printf("host: TestNestedCalls start!\n");
    HostNestCalls((void*)&args);
    if (args.ret != 0)
    {
        printf("Error: failed to complete host nested calls.\n");
        exit(1);
    }

    printf("host: TestNestedCalls end!\n\n");
    return;
}

int main(int argc, const char* argv[])
{
    OE_Result result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf(
        "=== This program is used to test nest calls and hardware exception "
        "behavior in nest calls.");

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(argv[1], flags, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    printf("Regular nest calls test without exception.\n");
    for (int i = 1; i < 17; i++)
    {
        TestNestedCalls(0, i);
    }

    TestNestedCalls(0, 32);
    TestNestedCalls(0, 64);

    // Skip the tests not suitable for simulation mode.
    if ((flags & OE_FLAG_SIMULATE) != 0)
    {
        printf("Skip the hardware exception tests not suitable for simulation"
            "mode.\n");
    }
    else
    {
        printf(
            "Test nest calls test with exception inside enclave for each call "
            "in.\n");
        for (int i = 1; i < 17; i++)
        {
            TestNestedCalls(1, i);
        }

        TestNestedCalls(1, 32);
        TestNestedCalls(1, 64);
    }

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (NestedCall)\n");

    return 0;
}
