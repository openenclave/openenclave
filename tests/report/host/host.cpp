// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/aesm.h>
#include <openenclave/bits/error.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/tests.h>
#include <openenclave/bits/utils.h>
#include <openenclave/host.h>
#include "../../../host/quote.h"
#include "../common/tests.cpp"

#define SKIP_RETURN_CODE 2

int main(int argc, const char* argv[])
{
    SGX_TargetInfo targetInfo;
    OE_Result result;
    OE_Enclave* enclave = NULL;

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = OE_GetCreateFlags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(report)\n");
        return SKIP_RETURN_CODE;
    }

    /* Create the enclave */
    if ((result = OE_CreateEnclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        OE_PutErr("OE_CreateEnclave(): result=%u", result);
    }

    /* Initialize the target info */
    {
        if ((result = SGX_GetQETargetInfo(&targetInfo)) != OE_OK)
        {
            OE_PutErr("SGX_GetQETargetInfo(): result=%u", result);
        }
    }

    /*
     * Host API tests.
     */
    g_Enclave = enclave;
    TestLocalReport(&targetInfo);
    TestRemoteReport(NULL);
    TestParseReportNegative(NULL);
    TestLocalVerifyReport(NULL);

    /*
     * Enclave API tests.
     */

    OE_TEST(OE_CallEnclave(enclave, "TestLocalReport", &targetInfo) == OE_OK);

    OE_TEST(OE_CallEnclave(enclave, "TestRemoteReport", &targetInfo) == OE_OK);

    OE_TEST(
        OE_CallEnclave(enclave, "TestParseReportNegative", &targetInfo) ==
        OE_OK);

    OE_TEST(
        OE_CallEnclave(enclave, "TestLocalVerifyReport", &targetInfo) == OE_OK);

    /* Terminate the enclave */
    if ((result = OE_TerminateEnclave(enclave)) != OE_OK)
    {
        OE_PutErr("OE_TerminateEnclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
