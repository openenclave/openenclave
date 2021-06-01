// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include "../host/sgx/cpuid.h"
#include "pf_gp_exceptions_u.h"

static bool _is_misc_region_supported()
{
    uint32_t eax, ebx, ecx, edx;
    eax = ebx = ecx = edx = 0;

    // Obtain feature information using CPUID
    oe_get_cpuid(CPUID_SGX_LEAF, 0x0, &eax, &ebx, &ecx, &edx);

    // Check if EXINFO is supported by the processor
    if (!(ebx & CPUID_SGX_MISC_EXINFO_MASK))
        return false;
    else
        return true;
}

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

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_pf_gp_exceptions_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    /* The enclave creation should succeed on both SGX1 and SGX2 machines. */
    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if (_is_misc_region_supported())
    {
        result = enc_pf_gp_exceptions(enclave, &return_value);
        if (result != OE_OK)
            oe_put_err("oe_call_enclave() failed: result=%u", result);

        OE_TEST(return_value == 0);
    }
    else
        printf("CPU does not support the CapturePFGPExceptions=1 "
               "configuration. Skip "
               "the test ECALL.\n");

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (pf_gp_exceptions)\n");

    return 0;
}
