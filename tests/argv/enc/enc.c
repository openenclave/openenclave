// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/argv.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "argv_t.h"

static void _test(const char* argv[], size_t argc)
{
    void* buf = NULL;
    size_t buf_size = 1;
    char** argv_out;

    OE_TEST(oe_argv_to_buffer(argv, argc, &buf, &buf_size) == OE_OK);

    if (argc == 0)
    {
        OE_TEST(buf == NULL);
        OE_TEST(buf_size == 0);

        OE_TEST(
            oe_buffer_to_argv(buf, buf_size, &argv_out, argc, malloc, free) ==
            OE_INVALID_PARAMETER);
    }
    else
    {
        OE_TEST(buf != NULL);
        OE_TEST(buf_size != 0);

        OE_TEST(
            oe_buffer_to_argv(buf, buf_size, &argv_out, argc, malloc, free) ==
            OE_OK);

        for (size_t i = 0; i < argc; i++)
        {
            OE_TEST(argv_out[i] != NULL);
            OE_TEST(strcmp(argv[i], argv_out[i]) == 0);
        }

        OE_TEST(argv[argc] == argv_out[argc]);

        free(buf);
        free(argv_out);
    }
}

void test_argv_ecall(void)
{
    /* Test an argv[] array with three entries. */
    {
        const char* argv[] = {
            "red",
            "green",
            "blue",
            NULL,
        };
        _test(argv, OE_COUNTOF(argv) - 1);
    };

    /* Test an argv[] array zero entries. */
    {
        const char* argv[] = {
            NULL,
        };
        _test(argv, OE_COUNTOF(argv) - 1);
    };

    /* Test an argv[] array empty elements. */
    {
        const char* argv[] = {
            "",
            "",
            "",
            "",
            "",
            "",
            "",
            NULL,
        };
        _test(argv, OE_COUNTOF(argv) - 1);
    };
}

OE_SET_ENCLAVE_SGX(
    1,    /* ProductID */
    1,    /* SecurityVersion */
    true, /* Debug */
    1024, /* NumHeapPages */
    1024, /* NumStackPages */
    2);   /* NumTCS */
