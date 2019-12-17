// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../../host/strings.h"
#include "sbrk_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    result = oe_create_sbrk_enclave(argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    result = test_sbrk(enclave);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (sbrk)\n");

    return 0;
}
