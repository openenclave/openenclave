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

void TestCppException(OE_Enclave* enclave)
{
    OE_Result result;
    Args args;

    printf("=== %s() \n", __FUNCTION__);
    result = OE_CallEnclave(enclave, "Test", &args);
    OE_TEST(result == OE_OK);
    OE_TEST(args.ret == 0);
}

void TestUnhandledException(
    OE_Enclave* enclave,
    unhandled_exception_func_num func_num)
{
    OE_Result result;
    Args args;
    args.func_num = func_num;

    printf("=== %s(%d)  \n", __FUNCTION__, func_num);
    result = OE_CallEnclave(enclave, "TestUnhandledException", &args);
    OE_TEST(result == OE_ENCLAVE_ABORTING);
    OE_TEST(args.ret == 0);
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    printf(
        "=== This program is used to test basic cpp exception "
        "functionalities.\n");

    const uint32_t flags = OE_GetCreateFlags();

    if ((result = OE_CreateEnclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    TestCppException(enclave);

    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed regular cpp exception tests.\n");

    // Test the un-handled exceptions.
    unhandled_exception_func_num func_nums[] = {
        EXCEPTION_SPECIFICATION, EXCEPTION_IN_UNWIND, UNHANDLED_EXCEPTION,
    };

    for (uint32_t i = 0; i < OE_COUNTOF(func_nums); i++)
    {
        if ((result = OE_CreateEnclave(
                 argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
            OE_OK)
        {
            OE_PutErr("OE_CreateEnclave(): result=%u", result);
        }

        TestUnhandledException(enclave, func_nums[i]);

        if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
        {
            OE_PutErr("OE_TerminateEnclave(): result=%u", result);
        }

        printf(
            "=== passed unhandled cpp exception tests (%d).\n", func_nums[i]);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
