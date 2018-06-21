// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/linux/cpuid_count.h"
#include "../args.h"

#define SKIP_RETURN_CODE 2

void TestVectorException(oe_enclave_t* enclave)
{
    TestVectorExceptionArgs args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;
    oe_result_t result = oe_call_enclave(enclave, "TestVectorException", &args);
    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    if (args.ret != 0)
        oe_put_err("ECALL TestVectorException failed args.result=%d", args.ret);

    OE_TEST(args.ret == 0);
}

void TestSigillHandling(oe_enclave_t* enclave)
{
    TestSigillHandlingArgs args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;

    oe_result_t result = oe_call_enclave(enclave, "TestSigillHandling", &args);
    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    if (args.ret != 0)
        oe_put_err("ECALL TestSigillHandling failed args.result=%d", args.ret);

    OE_TEST(args.ret == 0);

    // Verify that the enclave cached CPUID values match host's
    for (int i = 0; i < OE_CPUID_LEAF_COUNT; i++)
    {
        uint32_t cpuidInfo[OE_CPUID_REG_COUNT];
        memset(cpuidInfo, 0, sizeof(cpuidInfo));
        int supported = __get_cpuid_count(
            i,
            0,
            &cpuidInfo[OE_CPUID_RAX],
            &cpuidInfo[OE_CPUID_RBX],
            &cpuidInfo[OE_CPUID_RCX],
            &cpuidInfo[OE_CPUID_RDX]);

        if (!supported)
            oe_put_err(
                "Test machine does not support CPUID leaf %x expected by "
                "TestSigillHandling.\n",
                i);

        for (int j = 0; j < OE_CPUID_REG_COUNT; j++)
        {
            OE_TEST(cpuidInfo[j] == args.cpuidTable[i][j]);
        }
    }
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf(
        "=== This program is used to test basic vector exception "
        "functionalities.\n");

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(VectorException)\n");
        return SKIP_RETURN_CODE;
    }

    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    OE_TEST(
        oe_call_enclave(enclave, "TestCpuidInGlobalConstructors", NULL) ==
        OE_OK);

    TestVectorException(enclave);
    TestSigillHandling(enclave);

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (VectorException)\n");

    return 0;
}
