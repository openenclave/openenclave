// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "args.h"
#include "ocalls.h"

void Test(OE_Enclave* enclave)
{
    Args args;
    args.ret = 1;
    args.test = NULL;
    OE_Result result = OE_CallEnclave(enclave, "Test", &args);
    OE_TEST(result == OE_OK);

    if (args.ret == 0)
    {
        printf("PASSED: %s\n", args.test);
    }
    else
    {
        printf("FAILED: %s (ret=%d)\n", args.test, args.ret);
        abort();
    }
}

static void _ExitOCall(uint64_t argIn, uint64_t* argOut)
{
    exit(argIn);
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    uint32_t flags = OE_GetCreateFlags();

    // Check argument count:
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s\n", argv[0], argv[1]);

    // Create the enclave:
    if ((result = OE_CreateEnclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    // Register to handle OCALL_EXIT from tests.
    OE_RegisterOCall(OCALL_EXIT, _ExitOCall);

    // Invoke "Test()" in the enclave.
    Test(enclave);

    // Shutdown the enclave.
    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);

    printf("\n");

    return 0;
}
