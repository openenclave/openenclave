// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <cassert>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include "../args.h"

static oe_enclave_t* enclave;

int main(int argc, const char* argv[])
{
    oe_result_t result;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_enclave(
             argv[1],
             OE_ENCLAVE_TYPE_SGX,
             flags,
             NULL,
             0,
             NULL,
             0,
             &enclave)) != OE_OK)
    {
        oe_put_err("oe_create_enclave(): result=%u", result);
        return 1;
    }

    /* Invoke tests */
    {
        oe_result_t res = OE_FAILURE;

        result = oe_call_enclave(enclave, "TestAllocaDealloc", &res);
        OE_TEST(result == OE_OK);
        OE_TEST(res == OE_OK);
    }

    oe_terminate_enclave(enclave);

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
