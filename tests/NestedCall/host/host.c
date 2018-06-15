// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../args.h"

oe_enclave_t* enclave = NULL;

OE_OCALL void HostNestCalls(void* args_)
{
    oe_result_t result;
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
    Args new_args;
    memset(&new_args, 0, sizeof(new_args));
    new_args.ret = -1;
    new_args.depth = args->depth - 1;
    new_args.test_eh = args->test_eh;
    char str[256];
    sprintf(str, "Nested call depth [%d].", new_args.depth);

    if (!(new_args.in = strdup(str)))
    {
        fprintf(stderr, "strdup() failed");
        exit(1);
    }

    if ((result = oe_call_enclave(enclave, "EnclaveNestCalls", &new_args)) !=
        OE_OK)
    {
        fprintf(stderr, "oe_call_enclave() failed: result=%u", result);
        exit(1);
    }

    if (new_args.ret != 0)
    {
        fprintf(stderr, "ECALL failed newArgs.result=%d", new_args.ret);
        exit(1);
    }

    if (new_args.in)
    {
        free((char*)new_args.in);
        new_args.in = NULL;
    }

    if (new_args.out)
    {
        free((char*)new_args.out);
        new_args.out = NULL;
    }

    args->ret = 0;

    printf("host: HostNestCalls depth [%d] returned!.\n", args->depth);
    return;
}

void TestNestedCalls(int test_eh, int depth)
{
    // oe_result_t result;
    Args args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;
    args.test_eh = test_eh;
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
    oe_result_t result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf(
        "=== This program is used to test nest calls and hardware exception "
        "behavior in nest calls.");

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    printf("Regular nest calls test without exception.\n");
    for (int i = 1; i < 17; i++)
    {
        TestNestedCalls(0, i);
    }

    TestNestedCalls(0, 32);
    TestNestedCalls(0, 64);

    // Skip the tests not suitable for simulation mode.
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "Skip the hardware exception tests not suitable for simulation"
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

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (NestedCall)\n");

    return 0;
}
