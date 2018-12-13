// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define MEM_MIN_CAP 1
#include <openenclave/internal/mem.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>

void TestMem(mem_t* m)
{
    OE_TEST(mem_cpy(m, "hijk", 4) == 0);
    OE_TEST(mem_size(m) == 4);
    OE_TEST(mem_cap(m) >= 4);
    OE_TEST(memcmp(mem_ptr(m), "hijk", 4) == 0);

    OE_TEST(mem_append(m, "lmnop", 5) == 0);
    OE_TEST(mem_size(m) == 9);
    OE_TEST(mem_cap(m) >= 9);
    OE_TEST(memcmp(mem_ptr(m), "hijklmnop", 9) == 0);

    OE_TEST(mem_insert(m, 0, "abcdefg", 7) == 0);
    OE_TEST(mem_size(m) == 16);
    OE_TEST(mem_cap(m) >= 16);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnop", 16) == 0);

    OE_TEST(mem_append(m, "qrstuv", 6) == 0);
    OE_TEST(mem_size(m) == 22);
    OE_TEST(mem_cap(m) >= 22);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuv", 22) == 0);

    OE_TEST(mem_append(m, "wxyz", 4) == 0);
    OE_TEST(mem_size(m) == 26);
    OE_TEST(mem_cap(m) >= 26);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    OE_TEST(mem_remove(m, 22, 4) == 0);
    OE_TEST(mem_size(m) == 22);
    OE_TEST(mem_cap(m) >= 22);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuv", 22) == 0);

    OE_TEST(mem_append(m, "wxyz", 4) == 0);
    OE_TEST(mem_size(m) == 26);
    OE_TEST(mem_cap(m) >= 26);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    OE_TEST(mem_remove(m, 0, 7) == 0);
    OE_TEST(mem_size(m) == 19);
    OE_TEST(mem_cap(m) >= 19);
    OE_TEST(memcmp(mem_ptr(m), "hijklmnopqrstuvwxyz", 19) == 0);

    OE_TEST(mem_prepend(m, "abcdefg", 7) == 0);
    OE_TEST(mem_size(m) == 26);
    OE_TEST(mem_cap(m) >= 26);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    OE_TEST(mem_prepend(m, NULL, 1) == 0);
    OE_TEST(mem_size(m) == 27);
    OE_TEST(mem_cap(m) >= 27);
    OE_TEST(memcmp(mem_ptr(m), "\0abcdefghijklmnopqrstuvwxyz", 27) == 0);

    OE_TEST(mem_append(m, NULL, 1) == 0);
    OE_TEST(mem_size(m) == 28);
    OE_TEST(mem_cap(m) >= 28);
    OE_TEST(memcmp(mem_ptr(m), "\0abcdefghijklmnopqrstuvwxyz\0", 28) == 0);

    OE_TEST(mem_remove(m, 0, 1) == 0);
    OE_TEST(mem_remove(m, mem_size(m) - 1, 1) == 0);
    OE_TEST(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    OE_TEST(mem_resize(m, 7) == 0);
    OE_TEST(mem_size(m) == 7);
    OE_TEST(mem_cap(m) >= 7);
    OE_TEST(memcmp(mem_ptr(m), "abcdefg", 7) == 0);

    OE_TEST(mem_append(m, NULL, 1) == 0);
    OE_TEST(mem_size(m) == 8);
    OE_TEST(memcmp(mem_ptr(m), "abcdefg\0", 8) == 0);

    printf("=== passed TestMem()\n");
}

int main()
{
    /* TestMem dynamic */
    {
        mem_t m;
        OE_TEST(mem_dynamic(&m, NULL, 0, 0) == 0);
        OE_TEST(mem_type(&m) == MEM_TYPE_DYNAMIC);
        TestMem(&m);
        mem_free(&m);
    }

    /* TestMem static */
    {
        unsigned char buf[32];
        mem_t m;
        OE_TEST(mem_static(&m, buf, sizeof(buf)) == 0);
        OE_TEST(mem_type(&m) == MEM_TYPE_STATIC);
        TestMem(&m);
    }

    /* TestMem dynamic initializer expression */
    {
        mem_t m = MEM_DYNAMIC_INIT;
        OE_TEST(mem_type(&m) == MEM_TYPE_DYNAMIC);
        TestMem(&m);
        mem_free(&m);
    }

    printf("=== passed all tests (mem)\n");

    return 0;
}
