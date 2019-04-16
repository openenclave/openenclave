// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/strings.h"
#include "typeinfo_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    int retval;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    r = oe_create_typeinfo_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = test_typeinfo(enclave, &retval);
    OE_TEST(r == OE_OK);
    OE_TEST(retval == 0);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (echo)\n");

    return 0;
}
