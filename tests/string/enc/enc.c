// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/string.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/tests.h>

static void _test_strnsub()
{
    /* Test expansion replacement */
    {
        char str[15] = "AbAbAbAbA";
        size_t size = oe_strnsub(str, sizeof(str), "A", "AA");
        OE_TEST(oe_strcmp(str, "AAbAAbAAbAAbAA") == 0);
        OE_TEST(size == 15);
    }

    /* Test shrinkage replacement */
    {
        char str[20] = "AAAbAAAbAAAbAAAbAAA";
        size_t size = oe_strnsub(str, sizeof(str), "AAA", "A");
        OE_TEST(oe_strcmp(str, "AbAbAbAbA") == 0);
        OE_TEST(size == 10);
    }

    /* Test shrinkage replacement with empty string */
    {
        char str[20] = "AAAbAAAbAAAbAAAbAAA";
        size_t size = oe_strnsub(str, sizeof(str), "AAA", "");
        OE_TEST(oe_strcmp(str, "bbbb") == 0);
        OE_TEST(size == 5);
    }

    /* Test expansion replacement with string overflow */
    {
        char str[10] = "AbAbAbAbA";
        size_t size = oe_strnsub(str, sizeof(str), "A", "AA");
        OE_TEST(size == 15);
    }

    /* Test zero-sized pattern */
    {
        char str[10] = "AbAbAbAbA";
        size_t size = oe_strnsub(str, sizeof(str), "", "AA");
        OE_TEST(size == (size_t)-1);
    }

    /* Test full-string resplacement */
    {
        char str[16] = "Full";
        size_t size = oe_strnsub(str, sizeof(str), "Full", "Empty");
        OE_TEST(oe_strcmp(str, "Empty") == 0);
        OE_TEST(size == 6);
    }
}

OE_ECALL void Test(void* args)
{
    _test_strnsub();
}
