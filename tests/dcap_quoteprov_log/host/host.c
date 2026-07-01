// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <openenclave/trace.h>

#include <stdio.h>
#include "dcap_quoteprov_log_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_dcap_quoteprov_log_enclave(
             argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if (!oe_sgx_has_quote_provider())
    {
        fprintf(stdout, "Could not find dcap_quoteprov: lib\n");
        return 0;
    }
    else
    {
        OE_TEST(oe_set_host_log_level(OE_LOG_LEVEL_WARNING) == OE_OK);
        OE_TEST(
            oe_set_enclave_log_level(enclave, OE_LOG_LEVEL_WARNING) == OE_OK);
        // Get evidence.
        OE_TEST(generate_evidence(enclave) == OE_OK);
    }

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    return 0;
}
