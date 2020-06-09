// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

#include "oesign_test_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    bool is_signed = false;

    if (argc != 2)
    {
        oe_put_err("Usage: %s enclave_image_path\n", argv[0]);
    }

    // Create the enclave
    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_oesign_test_enclave(
             argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_crypto_enclave(): result=%u", result);
    }

    if (flags & OE_ENCLAVE_FLAG_SIMULATE)
    {
        /* Skip MRSIGNER check because the enclave call to oe_get_report is not
         * supported in simulation mode
         */
        printf(
            "Skipping enclave report MRSIGNER check in simulation mode...\n");
    }
    else
    {
        if ((result = is_test_signed(enclave, &is_signed)) != OE_OK)
        {
            oe_put_err("verify_signed() failed: result=%u", result);
        }

        if (!is_signed)
        {
            oe_put_err("%s is signed with a default debug signature", argv[1]);
        }
    }

    if ((result = oe_terminate_enclave(enclave)) != OE_OK)
    {
        oe_put_err("oe_terminate_enclave() failed: %u", result);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
