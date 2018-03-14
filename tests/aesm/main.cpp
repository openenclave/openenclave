// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/aesm.h>
#include <openenclave/bits/tests.h>
#include <openenclave/host.h>
#include <stdio.h>
#include <stdlib.h>

#define SKIP_RETURN_CODE 2

int main(int argc, const char* argv[])
{
    AESM* aesm;

    const uint32_t flags = OE_GetCreateFlags();
    if ((flags & OE_FLAG_SIMULATE) != 0)
    {
        printf(
            "=== Skipped unsupported test in simulation mode "
            "(aesm)\n");
        return SKIP_RETURN_CODE;
    }
    
    if (!(aesm = AESMConnect()))
    {
        fprintf(stderr, "%s: failed to connect\n", argv[0]);
        exit(1);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
