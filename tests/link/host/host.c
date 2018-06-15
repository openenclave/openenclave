// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>

int main(int argc, const char* argv[])
{
    oe_result_t result = OE_FAILURE;
    oe_enclave_t* enclave = NULL;
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }
    
    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    static uint8_t report[OE_MAX_REPORT_SIZE];
    uint32_t size = OE_MAX_REPORT_SIZE;

    // Create a local report.
    OE_TEST(oe_get_report(enclave, 0, NULL, 0, NULL, 0, report, &size) == OE_OK);

    // Eventhough the enclave does not use any functionality from
    // oeenclave, oe_verify_report must exist in the enclave.
    // Call the host side oe_verify_report which in turn uses the
    // enclave side implementation.
    OE_TEST(oe_verify_report(enclave, report, size, NULL) == OE_OK);

    oe_terminate_enclave(enclave);
    printf("=== passed all tests (echo)\n");

    return 0;
}
