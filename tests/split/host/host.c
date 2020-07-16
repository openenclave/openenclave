// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "split_u.h"

int main(int argc, const char* argv[])
{
    oe_result_t r;
    oe_enclave_t* enclave = NULL;
    const oe_enclave_type_t type = OE_ENCLAVE_TYPE_SGX;
    const uint32_t flags = oe_get_create_flags();
    int retval;
    char path[1024];

    if (argc != 3)
    {
        fprintf(stderr, "Usage: %s <enclave> <image>\n", argv[0]);
        return 1;
    }

    strcpy(path, argv[1]);
    strcat(path, ":");
    strcat(path, argv[2]);

    r = oe_create_split_enclave(path, type, flags, NULL, 0, &enclave);
    OE_TEST(r == OE_OK);

    r = split_ecall(enclave, &retval);
    OE_TEST(r == 0);

    r = oe_terminate_enclave(enclave);
    OE_TEST(r == OE_OK);

    printf("=== passed all tests (split)\n");

    return 0;
}
