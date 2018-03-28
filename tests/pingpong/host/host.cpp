// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include "pingpong_u.h"

static bool gotPong = false;

OE_EXTERNC void Log(const char* str, uint64_t x)
{
    printf("LOG: %s: %lu\n", str, x);
}

void Pong(const char* in, char* out)
{
    // printf("Pong: %s %s\n", in, out);

    if (in && out)
    {
        if (strcmp(in, "String1") == 0 && strcmp(out, "String2") == 0)
        {
            gotPong = true;
        }
    }

    strcpy(out, in);
}

static char buf[128];

int main(int argc, const char* argv[])
{
    OE_Result result;
    OE_Enclave* enclave = NULL;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: %s ENCLAVE_PATH\n", argv[0]);
        return 1;
    }

    const uint32_t flags = OE_GetCreateFlags();

    result = OE_CreateEnclave(argv[1], OE_TYPE_SGX, flags, NULL, 0, &enclave);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: cannot create enclave: %s\n", argv[0], argv[1]);
        return 1;
    }

    strcpy(buf, "String2");
    result = Ping(enclave, "String1", buf);
    if (result != OE_OK)
    {
        fprintf(stderr, "%s: Ping Failed\n", argv[0]);
        return 1;
    }

    OE_TerminateEnclave(enclave);

    if (!gotPong)
        fprintf(stderr, "%s: never received pong request\n", argv[0]);

    fprintf(stdout, "=== passed all tests (pingpong)\n");

    return 0;
}
