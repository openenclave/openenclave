// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "write_with_barrier_u.h"

int main(int argc, const char* argv[])
{
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    OE_TEST(
        oe_create_write_with_barrier_enclave(
            argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave) == OE_OK);

    OE_TEST(enc_write_with_barrier(enclave) == OE_OK);

    OE_TEST(oe_terminate_enclave(enclave) == OE_OK);

    printf("=== passed all tests (write_with_barrier)\n");

    return 0;
}
