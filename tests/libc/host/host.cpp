// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

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

void Test(oe_enclave_t* enclave)
{
    Args args;
    args.ret = 1;
    args.test = NULL;
    oe_result_t result = oe_call_enclave(enclave, "Test", &args);
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

static int _GetOpt(
    int& argc,
    const char* argv[],
    const char* name,
    const char** arg = NULL)
{
    for (int i = 0; i < argc; i++)
    {
        if (strcmp(argv[i], name) == 0)
        {
            if (!arg)
            {
                memmove(
                    (void*)&argv[i], &argv[i + 1], (argc - i) * sizeof(char*));
                argc--;
                return 1;
            }

            if (i + 1 == argc)
                return -1;

            *arg = argv[i + 1];
            memmove(
                (char**)&argv[i], &argv[i + 2], (argc - i - 1) * sizeof(char*));
            argc -= 2;
            return 1;
        }
    }

    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    uint32_t flags = OE_ENCLAVE_FLAG_DEBUG;

    // Check for the --sim option:
    if (_GetOpt(argc, argv, "--simulate") == 1)
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    else
        flags = oe_get_create_flags();

    // Check argument count:
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s\n", argv[0], argv[1]);

    // Create the enclave:
    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_puterr("oe_create_enclave(): result=%u", result);

    // Register to handle OCALL_EXIT from tests.
    oe_register_ocall(OCALL_EXIT, _ExitOCall);

    // Invoke "Test()" in the enclave.
    Test(enclave);

    // Shutdown the enclave.
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_puterr("oe_terminate_enclave(): result=%u", result);

    printf("\n");

    return 0;
}
