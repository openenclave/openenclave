// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <iostream>
#include <vector>
#include "SampleApp_u.h"

const char* Message = "Hello world from Host\n\0";

int unsecure_str_patching(const char* src, char* dst, size_t dst_length)
{
    size_t running_length = dst_length;
    while (running_length > 0 && *src != '\0')
    {
        *dst = *src;
        running_length--;
        src++;
        dst++;
    }
    const char* ptr = Message;
    while (running_length > 0 && *ptr != '\0')
    {
        *dst = *ptr;
        running_length--;
        ptr++;
        dst++;
    }
    if (running_length < 1)
    {
        return -1;
    }
    *dst = '\0';
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
            "Usage: SampleAppHost.exe <path to  packaged enc/dev dll>\n"
            "Example: SampleAppHost.exe SampleApp.dev.pkg\\SampleApp.dll\n");
        return 1;
    }

    const uint32_t flags = oe_get_create_flags();

    result = oe_create_SampleApp_enclave(
        argv[1], OE_ENCLAVE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "Could not create enclave, result=%d\n", result);
        return 1;
    }
    char dst[1024];
    const char* src = "My First App\n";
    int res = -1;
    OE_TEST(
        secure_str_patching(enclave, &res, src, dst, OE_COUNTOF(dst)) == OE_OK);

    if (res != 0)
    {
        fprintf(stderr, "%s: enclave called failed\n", argv[0]);
        exit(1);
    }

    const char expect[] = "My First App\n"
                          "Hello world from Enclave\n"
                          "My First App\n"
                          "Hello world from Host\n";

    if (strcmp(dst, expect) != 0)
    {
        fprintf(stderr, "%s: returned string don't match\n", argv[0]);
        return 1;
    }

    if (oe_terminate_enclave(enclave) != OE_OK)
    {
        fprintf(stderr, "oe_terminate_enclave(): failed: result=%d\n", result);
        return 1;
    }

    printf("=== passed all tests (SampleApp)\n");

    return 0;
}
