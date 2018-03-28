// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <cpuid.h>
#include <limits.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../args.h"

#define SKIP_RETURN_CODE 2

void TestVectorException(OE_Enclave* enclave)
{
    TestVectorExceptionArgs args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;
    OE_Result result = OE_CallEnclave(enclave, "TestVectorException", &args);
    if (result != OE_OK)
        OE_PutErr("OE_CallEnclave() failed: result=%u", result);

    if (args.ret != 0)
        OE_PutErr("ECALL TestVectorException failed args.result=%d", args.ret);

    OE_TEST(args.ret == 0);
}

void TestSigillHandling(OE_Enclave* enclave)
{
    TestSigillHandlingArgs args;
    memset(&args, 0, sizeof(args));
    args.ret = -1;
    OE_Result result = OE_CallEnclave(enclave, "TestSigillHandling", &args);
    if (result != OE_OK)
        OE_PutErr("OE_CallEnclave() failed: result=%u", result);

    if (args.ret != 0)
        OE_PutErr("ECALL TestSigillHandling failed args.result=%d", args.ret);

    OE_TEST(args.ret == 0);

    // Verify that the enclave cached CPUID values match host's
    for (int i = 0; i < OE_CPUID_LEAF_COUNT; i++)
    {
        uint32_t cpuidInfo[OE_CPUID_REG_COUNT];
        memset(cpuidInfo, 0, sizeof(cpuidInfo));
        int supported = __get_cpuid(
            i,
            &cpuidInfo[OE_CPUID_RAX],
            &cpuidInfo[OE_CPUID_RBX],
            &cpuidInfo[OE_CPUID_RCX],
            &cpuidInfo[OE_CPUID_RDX]);

        if (!supported)
            OE_PutErr(
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
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    printf(
        "=== This program is used to test basic vector exception "
        "functionalities.\n");

    const uint32_t flags = OE_GetCreateFlags();
    if ((flags & OE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(VectorException)\n");
        return SKIP_RETURN_CODE;
    }

    if ((result = OE_CreateEnclave(
             argv[1], OE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        OE_PutErr("OE_CreateEnclave(): result=%u", result);

    TestVectorException(enclave);
    TestSigillHandling(enclave);

    OE_TerminateEnclave(enclave);

    printf("=== passed all tests (VectorException)\n");

    return 0;
}
