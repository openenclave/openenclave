// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/host.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include "debug_malloc_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    {
        // Create enclave, allocate memory, but do not free it.
        if ((result = oe_create_debug_malloc_enclave(
                 argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
            OE_OK)
            oe_put_err("oe_create_enclave(): result=%u", result);

        OE_TEST(enc_allocate_memory(enclave) == OE_OK);

        // Unfreed memory will be reported as a leak.
        OE_TEST(oe_terminate_enclave(enclave) == OE_MEMORY_LEAK);
    }
    {
        // Create enclave, allocate memory, and free it.
        if ((result = oe_create_debug_malloc_enclave(
                 argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) !=
            OE_OK)
            oe_put_err("oe_create_enclave(): result=%u", result);

        OE_TEST(enc_allocate_memory(enclave) == OE_OK);
        OE_TEST(enc_cleanup_memory(enclave) == OE_OK);

        // No leaks will be reported.
        OE_TEST(oe_terminate_enclave(enclave) == OE_OK);
    }
    printf("=== passed all tests (debug_malloc)\n");

    return 0;
}
