// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "myfileio.h"

#include "mbed_u.h"

void Test(oe_enclave_t* enclave, int selftest)
{
    char path[1024];
    int return_value = 1;
    char out_testname[STRLEN];
    struct mbed_args args = {0};

    oe_result_t result = test(enclave, &return_value, out_testname, &args);
    OE_TEST(result == OE_OK);
    if (!selftest)
    {
        OE_TEST(args.total > 0);
        OE_TEST(args.total > args.skipped);
    }

    if (return_value == 0)
    {
        printf("PASSED: %s\n", out_testname);
    }
    else
    {
        printf("FAILED: %s (ret=%d)\n", out_testname, return_value);
        abort();
    }
}

void ocall_exit(int arg)
{
    exit(arg);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    char temp[500];
    oe_enclave_t* enclave = NULL;
    int selftest = 0;
    uint32_t flags = oe_get_create_flags();
    // Check argument count:
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf("=== %s: %s\n", argv[0], argv[1]);

    strcpy(temp, argv[1]);

    if (strstr(argv[1], "selftest"))
    {
        selftest = 1;
    }
    else
    {
        selftest = 0;
    }

    // Create the enclave:
    if ((result = oe_create_mbed_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    // Invoke "Test()" in the enclave.
    Test(enclave, selftest);

    // Shutdown the enclave.
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        oe_put_err("oe_terminate_enclave(): result=%u", result);

    printf("\n");

    return 0;
}
