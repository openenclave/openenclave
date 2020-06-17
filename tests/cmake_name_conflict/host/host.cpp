// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <cstdio>

#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/tests.h>

#include "name_conflict_u.h"

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

    result = oe_create_name_conflict_enclave(
        argv[1], type, flags, NULL, 0, &enclave);
    OE_TEST(result == OE_OK);

    result = test_name_conflict(enclave);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("===All tests pass (cmake_name_conflict).\n");

    return 0;
}
