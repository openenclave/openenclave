// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/tests.h>
#include "../args.h"

static void _test_strdup(void)
{
    {
        char* s = oe_strdup("hello");
        OE_TEST(s != NULL);
        OE_TEST(oe_strcmp(s, "hello") == 0);
        oe_free(s);
    }

    {
        char* s = oe_strdup("");
        OE_TEST(s != NULL);
        OE_TEST(oe_strcmp(s, "") == 0);
        oe_free(s);
    }

    {
        char* s = oe_strndup("hello world", 5);
        OE_TEST(s != NULL);
        OE_TEST(oe_strcmp(s, "hello") == 0);
        oe_free(s);
    }

    {
        char* s = oe_strndup("hello world", 0);
        OE_TEST(s != NULL);
        OE_TEST(oe_strcmp(s, "") == 0);
        oe_free(s);
    }
}

OE_ECALL void test_enclave(void* args_)
{
    args_t* args = (args_t*)args_;

    _test_strdup();

    args->ret = 0;
}
