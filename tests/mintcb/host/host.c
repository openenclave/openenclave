// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "mintcb_u.h"

int test_mintcb_ocall(int value)
{
    printf("host: test_mintcb_ocall()\n");
    fflush(stdout);
    return value;
}

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const int VALUE = 0x12345678;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    r = oe_create_mintcb_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    /* Call into the enclave. */
    {
        int retval = -1;
        r = test_mintcb_ecall(enclave, &retval, VALUE);
        OE_TEST(r == OE_OK);
        OE_TEST(retval == VALUE);
    }

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (mintcb)\n");

    return 0;
}
