// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <iostream>
#include <vector>

int EnclaveSecureStrPatching(
    OE_Enclave* Enclave,
    const char* src,
    char* dst,
    int dstLength);

const char* Message = "Hello world from Host\n\0";

int UnsecureStrPatching(const char* src, char* dst, int dstLength)
{
    int runningLength = dstLength;
    while (runningLength > 0 && *src != '\0')
    {
        *dst = *src;
        runningLength--;
        src++;
        dst++;
    }
    const char* ptr = Message;
    while (runningLength > 0 && *ptr != '\0')
    {
        *dst = *ptr;
        runningLength--;
        ptr++;
        dst++;
    }
    if (runningLength < 1)
    {
        return -1;
    }
    *dst = '\0';
    return 0;
}

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(
            stderr,
            "Usage: SampleAppHost.exe <path to  packaged enc/dev dll>\n"
            "Example: SampleAppHost.exe SampleApp.dev.pkg\\SampleApp.dll\n");
        return 1;
    }

    const uint32_t flags = OE_GetCreateFlags();

    result = OE_CreateEnclave(argv[1], OE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "Could not create enclave, result=%d\n", result);
        return 1;
    }
    char dst[1024];
    const char* src = "My First App\n";
    int res = EnclaveSecureStrPatching(enclave, src, dst, OE_COUNTOF(dst));

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

    if (OE_TerminateEnclave(enclave) != OE_OK)
    {
        fprintf(stderr, "OE_TerminateEnclave(): failed: result=%d\n", result);
        return 1;
    }

    printf("=== passed all tests (SampleApp)\n");

    return 0;
}
