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
    sgx_target_info_t targetInfo;
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    /* Check arguments */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(report)\n");
        return SKIP_RETURN_CODE;
    }

    /* Create the enclave */
    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
    }

    /* Initialize the target info */
    {
        if ((result = sgx_get_qetarget_info(&targetInfo)) != OE_OK)
        {
            oe_put_err("sgx_get_qetarget_info(): result=%u", result);
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

    OE_TEST(oe_call_enclave(enclave, "TestLocalReport", &targetInfo) == OE_OK);

    OE_TEST(oe_call_enclave(enclave, "TestRemoteReport", &targetInfo) == OE_OK);

    OE_TEST(
        oe_call_enclave(enclave, "TestParseReportNegative", &targetInfo) ==
        OE_OK);

    OE_TEST(
        oe_call_enclave(enclave, "TestLocalVerifyReport", &targetInfo) == OE_OK);

    /* Terminate the enclave */
    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave(): result=%u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
