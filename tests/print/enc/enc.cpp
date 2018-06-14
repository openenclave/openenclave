// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include "../args.h"

OE_ECALL void TestPrint(void* args_)
{
    TestPrintArgs* args = (TestPrintArgs*)args_;
    size_t n;

    /* Write to standard output */
    {
        oe_host_printf("oe_host_printf(stdout)\n");

        printf("printf(stdout)\n");

        n = fwrite("fwrite(stdout)\n", 1, 15, stdout);
        OE_TEST(n == 15);

        const char str[] = "__oe_host_print(stdout)\n";
        __oe_host_print(0, str, (size_t)-1);
        __oe_host_print(0, str, sizeof(str)-1);
    }

    /* Write to standard error */
    {
        n = fwrite("fwrite(stderr)\n", 1, 15, stderr);
        OE_TEST(n == 15);

        const char str[] = "__oe_host_print(stderr)\n";
        __oe_host_print(1, str, (size_t)-1);
        __oe_host_print(1, str, sizeof(str)-1);
    }

    args->rc = 0;
}
