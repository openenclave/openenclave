// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "non_debug_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    bool simulation_mode = false;

    if (argc < 2)
    {
        fprintf(
            stderr, "Usage: %s ENCLAVE_PATH [--simulation-mode]\n", argv[0]);
        return 1;
    }

    uint32_t flags = oe_get_create_flags();

    simulation_mode =
        (argc == 3 && (strcmp(argv[2], "--simulation-mode") == 0));

    if (simulation_mode)
    {
        // Force simulation mode if --simulation-mode is specified.
        flags |= OE_ENCLAVE_FLAG_SIMULATE;
    }

    // Remove debug flag.
    flags = flags & (~OE_ENCLAVE_FLAG_DEBUG);

    if ((result = oe_create_non_debug_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    OE_TEST(enc_fcn(enclave) == OE_OK);

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
    OE_TEST(result == OE_OK);

    printf(
        "=== ran non debug enclave in %s mode\n",
        simulation_mode ? "-simulation" : "hardware");

    return 0;
}
