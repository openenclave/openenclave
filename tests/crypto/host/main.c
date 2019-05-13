// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include <stdio.h>
#include "../tests.h"

const char* arg0;

int main(int argc, const char* argv[])
{
    OE_UNUSED(argc);
    arg0 = argv[0];

    /* Run the tests */
    TestAll();

    printf("=== passed all tests (%s)\n", arg0);

    return 0;
}
