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
#include "zigzag_u.h"

oe_enclave_t* enclaves[2];

void host_zag(void)
{
    printf("host zag!\n");
    enc_zag(enclaves[1], 1);
}

void host_bye(void)
{
    printf("host bye!\n") ;   
}


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

    if ((result = oe_create_zigzag_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclaves[0])) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    if ((result = oe_create_zigzag_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclaves[1])) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    printf("\n\n\n");
    enc_zig(enclaves[0], 0);
    printf("\n\n\n");

    result = oe_terminate_enclave(enclaves[0]);
    OE_TEST(result == OE_OK);

    result = oe_terminate_enclave(enclaves[1]);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (zigzag)\n");

    return 0;
}
