// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "wrfsbase_u.h"

oe_enclave_t* enclave;

void host_dummy()
{
}

int main(int argc, const char* argv[])
{
    oe_result_t result;

    if (argc != 3)
    {
        fprintf(
            stderr,
            "Usage: %s ENCLAVE_PATH testname negative_test(boolean)\n",
            argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    int simulation_mode = 0;
    int negative_test = atoi(argv[2]);

    if (flags & OE_ENCLAVE_FLAG_SIMULATE)
        simulation_mode = 1;

    if ((result = oe_create_wrfsbase_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if (!negative_test)
    {
        result = enc_wrfsbase(enclave, simulation_mode, 0);
        if (result != OE_OK)
            oe_put_err("oe_call_enclave() failed: result=%u", result);

        OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
    }
    else
    {
        result = enc_wrfsbase(enclave, simulation_mode, 1);
        if (result != OE_ENCLAVE_ABORTING)
            oe_put_err("oe_call_enclave() failed: result=%u", result);
    }

    printf("=== passed all tests (wrfsbase)\n");

    return 0;
}
