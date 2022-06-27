// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/sgx/tests.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include "stack_overflow_exception_u.h"

static bool enclave_stack_overflowed = false;

void host_notify_stack_overflowed()
{
    enclave_stack_overflowed = true;
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

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_stack_overflow_exception_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    /* The enclave creation should succeed on both SGX1 and SGX2 machines. */
    if (result != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if (flags & OE_ENCLAVE_FLAG_SIMULATE)
        printf("Simulation mode does not support exceptions. Skip the test "
               "ECALL.\n");
    else if (oe_sgx_is_misc_region_supported())
    {
        OE_TEST(enc_stack_overflow_exception(enclave) == OE_ENCLAVE_ABORTING);
        OE_TEST(enclave_stack_overflowed == true);

        OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
    }
    else
    {
        printf("CPU does not support the CapturePFGPExceptions=1 "
               "configuration. Skip the test ECALL.\n");

        OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
    }

    printf("=== passed all tests (stack_overflow_exception)\n");

    return 0;
}
