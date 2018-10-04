// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"

void TestCppException(oe_enclave_t* enclave)
{
    oe_result_t result;
    Args args;

    printf("=== %s() \n", __FUNCTION__);
    result = oe_call_enclave(enclave, "Test", &args);
    OE_TEST(result == OE_OK);
    OE_TEST(args.ret == 0);
}

void TestUnhandledException(
    oe_enclave_t* enclave,
    unhandled_exception_func_num func_num)
{
    oe_result_t result;
    Args args;
    args.func_num = func_num;

    printf("=== %s(%d)  \n", __FUNCTION__, func_num);
    result = oe_call_enclave(enclave, "TestUnhandledException", &args);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(args.ret == 0);
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf(
        "=== This program is used to test basic cpp exception "
        "functionalities.\n");

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             NULL,
             0,
             NULL,
             0,
             &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    TestCppException(enclave);

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed regular cpp exception tests.\n");

    // Test the un-handled exceptions.
    unhandled_exception_func_num func_nums[] = {
        EXCEPTION_SPECIFICATION, EXCEPTION_IN_UNWIND, UNHANDLED_EXCEPTION,
    };

    for (uint32_t i = 0; i < OE_COUNTOF(func_nums); i++)
    {
        if ((result = oe_create_enclave(
                 argv[1],
                 OE_ENCLAVE_TYPE_SGX,
                 flags,
                 NULL,
                 0,
                 NULL,
                 0,
                 &enclave)) != OE_OK)
        {
            oe_put_err("oe_create_enclave(): result=%u", result);
        }

        TestUnhandledException(enclave, func_nums[i]);

        if ((result = oe_terminate_enclave(enclave)) != OE_OK)
        {
            if (result != OE_MEMORY_LEAK)
                oe_put_err("oe_terminate_enclave(): result=%u", result);
        }

        printf(
            "=== passed unhandled cpp exception tests (%d).\n", func_nums[i]);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
