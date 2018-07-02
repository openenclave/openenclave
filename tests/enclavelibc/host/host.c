// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    args_t args;

    /* Check command line argument count */
    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    /* Create the enclave */
    {
        const uint32_t flags = oe_get_create_flags();
        const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;

        r = oe_create_enclave( argv[1], type, flags, NULL, 0, &enclave);
        OE_TEST(r == OE_OK);
    }

    /* Invoke the test function */
    args.ret = -1;
    r = oe_call_enclave(enclave, "test_enclave", &args);
    OE_TEST(r == OE_OK);
    OE_TEST(args.ret == 0);

    /* Terminate the enclave */
    oe_terminate_enclave(enclave);

    printf("=== passed all tests (echo)\n");

    return 0;
}
