// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/string.h>
#include <openenclave/internal/tests.h>

static void _test_string_substitute()
{
    /* Test expansion replacement */
    {
        char str[15] = "AbAbAbAbA";
        size_t size = oe_string_substitute(str, sizeof(str), "A", "AA");
        OE_TEST(oe_strcmp(str, "AAbAAbAAbAAbAA") == 0);
        OE_TEST(size == 15);
    }

    /* Test shrinkage replacement */
    {
        char str[20] = "AAAbAAAbAAAbAAAbAAA";
        size_t size = oe_string_substitute(str, sizeof(str), "AAA", "A");
        OE_TEST(oe_strcmp(str, "AbAbAbAbA") == 0);
        OE_TEST(size == 10);
    }

    /* Test shrinkage replacement with empty string */
    {
        char str[20] = "AAAbAAAbAAAbAAAbAAA";
        size_t size = oe_string_substitute(str, sizeof(str), "AAA", "");
        OE_TEST(oe_strcmp(str, "bbbb") == 0);
        OE_TEST(size == 5);
    }

    /* Test expansion replacement with string overflow */
    {
        char str[10] = "AbAbAbAbA";
        size_t size = oe_string_substitute(str, sizeof(str), "A", "AA");
        OE_TEST(size == 15);
    }

    /* Test zero-sized pattern */
    {
        char str[10] = "AbAbAbAbA";
        size_t size = oe_string_substitute(str, sizeof(str), "", "AA");
        OE_TEST(size == (size_t)-1);
    }

    /* Test full-string resplacement */
    {
        char str[16] = "Full";
        size_t size = oe_string_substitute(str, sizeof(str), "Full", "Empty");
        OE_TEST(oe_strcmp(str, "Empty") == 0);
        OE_TEST(size == 6);
    }
}

static void _test_string_insert()
{
    /* Insert at start */
    {
        char str[16] = "string";
        const char expect[] = "start string";
        size_t size = oe_string_insert(str, sizeof(str), 0, "start ");
        OE_TEST(oe_strcmp(str, expect) == 0);
        OE_TEST(size == sizeof(expect));
    }

    /* Insert at end */
    {
        char str[16] = "string";
        const char expect[] = "string end";
        size_t size = oe_string_insert(str, sizeof(str), (size_t)-1, " end");
        OE_TEST(oe_strcmp(str, expect) == 0);
        OE_TEST(size == sizeof(expect));
    }

    /* Insert in the middle */
    {
        char str[17] = "start end";
        const char expect[] = "start middle end";
        size_t size = oe_string_insert(str, sizeof(str), 6, "middle ");
        OE_TEST(oe_strcmp(str, expect) == 0);
        OE_TEST(size == sizeof(expect));
    }

    /* Insert an empty string at start */
    {
        char str[] = "string";
        const char expect[] = "string";
        size_t size = oe_string_insert(str, sizeof(str), 0, "");
        OE_TEST(oe_strcmp(str, expect) == 0);
        OE_TEST(size == sizeof(expect));
    }

    /* Insert an empty string at end */
    {
        char str[] = "string";
        const char expect[] = "string";
        size_t size = oe_string_insert(str, sizeof(str), 6, "");
        OE_TEST(oe_strcmp(str, expect) == 0);
        OE_TEST(size == sizeof(expect));
    }

    /* Insert into empty string */
    {
        char str[7] = "";
        const char expect[] = "string";
        size_t size = oe_string_insert(str, sizeof(str), 0, "string");
        OE_TEST(oe_strcmp(str, expect) == 0);
        OE_TEST(size == sizeof(expect));
    }

    /* Insert into empty string with overflow */
    {
        char str[1] = "";
        const char expect[] = "";
        size_t size = oe_string_insert(str, sizeof(str), 0, "string");
        OE_TEST(oe_strcmp(str, expect) == 0);
        OE_TEST(size == 7);
    }
}

OE_ECALL void Test(void* args)
{
    _test_string_substitute();
    _test_string_insert();
}
