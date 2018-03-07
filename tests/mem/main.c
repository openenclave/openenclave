// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define MEM_MIN_CAP 1
#include <assert.h>
#include <openenclave/bits/mem.h>
#include <stdio.h>

void TestMem(mem_t* m)
{
    assert(mem_cpy(m, "hijk", 4) == 0);
    assert(mem_size(m) == 4);
    assert(mem_cap(m) >= 4);
    assert(memcmp(mem_ptr(m), "hijk", 4) == 0);

    assert(mem_append(m, "lmnop", 5) == 0);
    assert(mem_size(m) == 9);
    assert(mem_cap(m) >= 9);
    assert(memcmp(mem_ptr(m), "hijklmnop", 9) == 0);

    assert(mem_insert(m, 0, "abcdefg", 7) == 0);
    assert(mem_size(m) == 16);
    assert(mem_cap(m) >= 16);
    assert(memcmp(mem_ptr(m), "abcdefghijklmnop", 16) == 0);

    assert(mem_append(m, "qrstuv", 6) == 0);
    assert(mem_size(m) == 22);
    assert(mem_cap(m) >= 22);
    assert(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuv", 22) == 0);

    assert(mem_append(m, "wxyz", 4) == 0);
    assert(mem_size(m) == 26);
    assert(mem_cap(m) >= 26);
    assert(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    assert(mem_remove(m, 22, 4) == 0);
    assert(mem_size(m) == 22);
    assert(mem_cap(m) >= 22);
    assert(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuv", 22) == 0);

    assert(mem_append(m, "wxyz", 4) == 0);
    assert(mem_size(m) == 26);
    assert(mem_cap(m) >= 26);
    assert(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    assert(mem_remove(m, 0, 7) == 0);
    assert(mem_size(m) == 19);
    assert(mem_cap(m) >= 19);
    assert(memcmp(mem_ptr(m), "hijklmnopqrstuvwxyz", 19) == 0);

    assert(mem_prepend(m, "abcdefg", 7) == 0);
    assert(mem_size(m) == 26);
    assert(mem_cap(m) >= 26);
    assert(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    assert(mem_prepend(m, NULL, 1) == 0);
    assert(mem_size(m) == 27);
    assert(mem_cap(m) >= 27);
    assert(memcmp(mem_ptr(m), "\0abcdefghijklmnopqrstuvwxyz", 27) == 0);

    assert(mem_append(m, NULL, 1) == 0);
    assert(mem_size(m) == 28);
    assert(mem_cap(m) >= 28);
    assert(memcmp(mem_ptr(m), "\0abcdefghijklmnopqrstuvwxyz\0", 28) == 0);

    assert(mem_remove(m, 0, 1) == 0);
    assert(mem_remove(m, mem_size(m) - 1, 1) == 0);
    assert(memcmp(mem_ptr(m), "abcdefghijklmnopqrstuvwxyz", 26) == 0);

    assert(mem_resize(m, 7) == 0);
    assert(mem_size(m) == 7);
    assert(mem_cap(m) >= 7);
    assert(memcmp(mem_ptr(m), "abcdefg", 7) == 0);

    assert(mem_append(m, NULL, 1) == 0);
    assert(mem_size(m) == 8);
    assert(memcmp(mem_ptr(m), "abcdefg\0", 8) == 0);

    printf("=== passed TestMem()\n");
}

int main(int argc, const char* argv[])
{
    /* TestMem dynamic */
    {
        mem_t m;
        assert(mem_dynamic(&m, NULL, 0, 0) == 0);
        assert(mem_type(&m) == MEM_TYPE_DYNAMIC);
        TestMem(&m);
        mem_free(&m);
    }

    /* TestMem static */
    {
        unsigned char buf[32];
        mem_t m;
        assert(mem_static(&m, buf, sizeof(buf)) == 0);
        assert(mem_type(&m) == MEM_TYPE_STATIC);
        TestMem(&m);
    }

    /* TestMem dynamic initializer expression */
    {
        mem_t m = MEM_DYNAMIC_INIT;
        assert(mem_type(&m) == MEM_TYPE_DYNAMIC);
        TestMem(&m);
        mem_free(&m);
    }

    printf("=== passed all tests (mem)\n");

    return 0;
}
