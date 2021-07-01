// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <iostream>
#include <vector>
#include "sgx_zerobase_u.h"

const char* message = "Hello world from Host\n\0";

int unsecure_string_patching(
    const char* source,
    char* output,
    size_t output_length)
{
    size_t running_length = output_length;
    while (running_length > 0 && *source != '\0')
    {
        *output = *source;
        running_length--;
        source++;
        output++;
    }
    const char* ptr = message;
    while (running_length > 0 && *ptr != '\0')
    {
        *output = *ptr;
        running_length--;
        ptr++;
        output++;
    }
    if (running_length < 1)
    {
        return -1;
    }
    *output = '\0';
    return 0;
}

int main(int argc, const char* argv[])
{
    oe_result_t result;
    oe_enclave_t* enclave = NULL;

    if (argc != 2)
    {
        fprintf(
            stderr,
            "Usage: sgx_zerobase_host.exe <path to  packaged enc/dev dll>\n"
            "Example: sgx_zerobase_host.exe "
            "sgx_zerobase_enc.dev.pkg\\sgx_zerobase_enc.dll\n");
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_sgx_zerobase_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "Could not create enclave, result=%d\n", result);
        return 1;
    }
    char output[1024];
    const char* source = "My First App\n";
    int res = -1;
    OE_TEST(
        secure_string_patching(
            enclave, &res, source, output, OE_COUNTOF(output)) == OE_OK);

    if (res != 0)
    {
        fprintf(stderr, "%s: enclave called failed\n", argv[0]);
        exit(1);
    }

    const char expect[] = "My First App\n"
                          "Hello world from Enclave\n"
                          "My First App\n"
                          "Hello world from Host\n";

    if (strcmp(output, expect) != 0)
    {
        fprintf(stderr, "%s: returned string don't match\n", argv[0]);
        return 1;
    }

    if (oe_terminate_enclave(enclave) != OE_OK)
    {
        fprintf(stderr, "oe_terminate_enclave(): failed: result=%d\n", result);
        return 1;
    }

    printf("=== passed all tests (sgx_zerobase)\n");

    return 0;
}
