// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "../args.h"

OE_ECALL void TestPrint(void* args_)
{
    TestPrintArgs* args = (TestPrintArgs*)args_;
    size_t n;

    /* Write to standard output */
    {
        OE_HostPrintf("OE_HostPrintf(stdout)\n");

        printf("printf(stdout)\n");

        n = fwrite("fwrite(stdout)\n", 1, 15, stdout);
        OE_TEST(n == 15);

        __OE_HostPrint(0, "__OE_HostPrint(stdout)\n", (size_t)-1);
        __OE_HostPrint(0, "__OE_HostPrint(stdout)\n", 23);
    }

    /* Write to standard error */
    {
        n = fwrite("fwrite(stderr)\n", 1, 15, stderr);
        OE_TEST(n == 15);

        __OE_HostPrint(1, "__OE_HostPrint(stderr)\n", (size_t)-1);
        __OE_HostPrint(1, "__OE_HostPrint(stderr)\n", 23);
    }

    args->rc = 0;
}
