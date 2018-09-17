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
#include "echo_u.h"

int host_echo(char* in, char* out, char* str1, char* str2, char str3[100])
{
    OE_TEST(strcmp(str1, "oe_host_strdup1") == 0);
    OE_TEST(strcmp(str2, "oe_host_strdup2") == 0);
    OE_TEST(strcmp(str3, "oe_host_strdup3") == 0);

    strcpy(out, in);

    return 0;
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

    if ((result = oe_create_enclave(
             argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave)) != OE_OK)
        oe_put_err("oe_create_enclave(): result=%u", result);

    char outParameter[100];
    int returnVal;

    result = enc_echo(enclave, &returnVal, "Hello World", outParameter);

    if (result != OE_OK)
        oe_put_err("oe_call_enclave() failed: result=%u", result);

    if (returnVal != 0)
        oe_put_err("ECALL failed args.result=%d", returnVal);

    if (strcmp("Hello World", outParameter) != 0)
        oe_put_err("ecall failed: %s != %s\n", "Hello World", outParameter);

    result = oe_terminate_enclave(enclave);
    OE_TEST(result == OE_OK);

    printf("=== passed all tests (echo)\n");

    return 0;
}
