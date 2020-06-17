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
    oe_result_t r;
    size_t buf_size_out = 1;

    r = oe_argv_to_buffer(argv, argc, NULL, 0, &buf_size_out);

    if (argc == 0)
    {
        OE_TEST(buf_size_out == 0);
    }
    else
    {
        void* buf;
        size_t buf_size;
        char** argv_out;

        OE_TEST(r == OE_BUFFER_TOO_SMALL);

        buf_size = buf_size_out;
        OE_TEST((buf = malloc(buf_size)));

        r = oe_argv_to_buffer(argv, argc, buf, buf_size, &buf_size_out);
        OE_TEST(r == OE_OK);

        r = oe_buffer_to_argv(buf, buf_size, &argv_out, argc, malloc, free);
        OE_TEST(r == OE_OK);

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
