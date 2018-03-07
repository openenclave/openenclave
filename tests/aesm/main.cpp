// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/aesm.h>
#include <stdio.h>
#include <stdlib.h>

int main(int argc, const char* argv[])
{
    AESM* aesm;

    if (!(aesm = AESMConnect()))
    {
        fprintf(stderr, "%s: failed to connect\n", argv[0]);
        exit(1);
    }

    printf("=== passed all tests (%s)\n", argv[0]);

    return 0;
}
