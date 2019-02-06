// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/elf.h>
#include <openenclave/internal/error.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <thread>
#include "no_tdata_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    elf64_t elf = {0};
    unsigned char* data = NULL;
    size_t size = 0;

    // Assert that .tdata section does not exist.
    OE_TEST(elf64_find_section(&elf, ".tdata", &data, &size) == -1);
    elf64_unload(&elf);

    const uint32_t flags = oe_get_create_flags();
    if ((result = oe_create_no_tdata_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (thread-local-no-tdata)\n");

    return 0;
}
