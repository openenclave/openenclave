// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include "print_t.h"

int enclave_test_print()
{
    size_t n;

    /* Write to standard output */
    {
        oe_host_printf("oe_host_printf(stdout)\n");

        printf("printf(stdout)\n");

        n = fwrite("fwrite(stdout)\n", 1, 15, stdout);
        OE_TEST(n == 15);
        int r = fputc('o', stdout);
        OE_TEST(r == 'o');
        /* Note that gcc seems to optimize fputs to fwrite, and fprintf to
           fputc, iff we ignore the result. */
        fprintf(stdout, "\n");
        r = fputs("", stdout);
        OE_TEST(r == 0);
        r = fputs("fputs(stdout)\n", stdout);
        OE_TEST(r >= 0);

        const char str[] = "oe_host_write(stdout)\n";
        oe_host_write(0, str, (size_t)-1);
        oe_host_write(0, str, sizeof(str) - 1);
    }

    /* Write to standard error */
    {
        n = fwrite("fwrite(stderr)\n", 1, 15, stderr);
        OE_TEST(n == 15);
        int r = fputc('e', stderr);
        OE_TEST(r == 'e');
        /* Note that gcc seems to optimize fputs to fwrite, and fprintf to
           fputc, iff we ignore the result. */
        fprintf(stderr, "\n");
        r = fputs("fputs(stderr)\n", stderr);
        OE_TEST(r >= 0);
        const char str[] = "oe_host_write(stderr)\n";
        oe_host_write(1, str, (size_t)-1);
        oe_host_write(1, str, sizeof(str) - 1);
    }

    return 0;
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
