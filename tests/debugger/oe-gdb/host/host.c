// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "oe_gdb_test_u.h"

#define SKIP_RETURN_CODE 2

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave1 = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();
    if ((flags & OE_ENCLAVE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(oe_gdb_test)\n");
        return SKIP_RETURN_CODE;
    }

    if ((result = oe_create_oe_gdb_test_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave1)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    {
        int c = 0;
        OE_TEST(enc_add(enclave1, &c, 5, 6) == OE_OK);

        // Test that the debugger was able to change the return value in the
        // enclave.
        OE_TEST(c == 10000);
    }

    result = oe_terminate_enclave(enclave1);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (oe-gdb)\n");

    return 0;
}
