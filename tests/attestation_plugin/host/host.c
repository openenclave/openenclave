// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

#include "../plugin/tests.h"
#include "plugin_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE\n", argv[0]);
        exit(1);
    }

    // Run test on the enclave.
    const uint32_t flags = oe_get_create_flags();

    result = oe_create_plugin_enclave(
        argv[1], OE_ENCLAVE_TYPE_AUTO, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    run_test(enclave);

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    // Run test on the host.
    test_run_all();

    return 0;
}
