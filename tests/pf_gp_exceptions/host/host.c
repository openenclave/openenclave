// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include "pf_gp_exceptions_u.h"

#ifdef _WIN32
static int is_on_windows = 1;
#else
static int is_on_windows = 0;
#endif

#define SKIP_RETURN_CODE 2

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    int return_value;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    uint32_t flags = oe_get_create_flags();
    flags &= ~(uint32_t)OE_ENCLAVE_FLAG_DEBUG;
    flags |= (uint32_t)OE_ENCLAVE_FLAG_DEBUG_AUTO;

    int is_misc_region_supported = oe_sgx_is_misc_region_supported();

    result = oe_create_pf_gp_exceptions_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);

    if (result == OE_PLATFORM_ERROR && !oe_sgx_is_flc_supported())
    {
        // creation of non-debug enclave may fail on non-FLC systems
        return SKIP_RETURN_CODE;
    }

    /* The enclave creation should succeed on both SGX1 and SGX2 machines. */
    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if (flags & OE_ENCLAVE_FLAG_SIMULATE)
        printf("Simulation mode does not support exceptions. Skip the test "
               "ECALL.\n");
    else
    {
        result = enc_pf_gp_exceptions(
            enclave, &return_value, is_misc_region_supported, is_on_windows);
        if (result != OE_OK)
            oe_put_err("oe_call_enclave() failed: result=%u", result);

        if (return_value == SKIP_RETURN_CODE)
            return SKIP_RETURN_CODE;

        OE_TEST(return_value == 0);
    }

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (pf_gp_exceptions)\n");

    return 0;
}
