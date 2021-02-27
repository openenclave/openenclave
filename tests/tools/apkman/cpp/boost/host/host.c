// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

#include "test_u.h"

int main(int argc, char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    int return_val;
    if (argc < 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    if ((result = oe_create_test_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    result = enc_main(enclave, &return_val, argc - 1, argv + 1);

    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    if (return_val != 0)
        oe_put_err("ECALL failed args.result=%d", return_val);

    result = oe_terminate_enclave(enclave);
    // C++ iostream leaks an object. Not sure if we can do anything about it.
    OE_TEST(result == OE_OK || result == OE_MEMORY_LEAK);

    printf("=== passed all tests (boost)\n");

    return 0;
}
