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
#include "../host/cpuid.h"

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
    // First, verify values being tested do not reach above max supported leaf.
    uint32_t cpuid_maxlevel[OE_CPUID_REG_COUNT];
    memset(cpuid_maxlevel, 0, sizeof(cpuid_maxlevel));
    oe_get_cpuid(
        0,
        0,
        &cpuid_maxlevel[OE_CPUID_RAX],
        &cpuid_maxlevel[OE_CPUID_RBX],
        &cpuid_maxlevel[OE_CPUID_RCX],
        &cpuid_maxlevel[OE_CPUID_RDX]);

    if (OE_CPUID_LEAF_COUNT - 1 > cpuid_maxlevel[OE_CPUID_RAX])
        oe_put_err(
            "Test machine does not support CPUID leaf %x expected by "
            "TestSigillHandling.\n",
            (OE_CPUID_LEAF_COUNT - 1));

    // Check all values.
    for (int i = 0; i < OE_CPUID_LEAF_COUNT; i++)
    {
        uint32_t cpuid_info[OE_CPUID_REG_COUNT];
        memset(cpuid_info, 0, sizeof(cpuid_info));
        oe_get_cpuid(
            i,
            0,
            &cpuid_info[OE_CPUID_RAX],
            &cpuid_info[OE_CPUID_RBX],
            &cpuid_info[OE_CPUID_RCX],
            &cpuid_info[OE_CPUID_RDX]);

        for (int j = 0; j < OE_CPUID_REG_COUNT; j++)
        {
            if (cpuid_info[j] != args.cpuid_table[i][j])
                printf(
                    "Failed: i=%d, j=%d, lhs=%d, rhs=%d\n",
                    i,
                    j,
                    cpuid_info[j],
                    args.cpuid_table[i][j]);

            OE_TEST(cpuid_info[j] == args.cpuid_table[i][j]);
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
