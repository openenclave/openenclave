// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdlib.h>
#include <string.h>
#include "all_t.h"

static uint64_t data[8] = {0x1112131415161718,
                           0x2122232425262728,
                           0x3132333435363738,
                           0x4142434445464748,
                           0x5152535455565758,
                           0x6162636465666768,
                           0x7172737475767778,
                           0x8182838485868788};

// Assert that the struct is copied by value, such that `s.ptr` is the
// address of `data[]` in the host (also passed via `ptr`).
void deepcopy_value(ShallowStruct s, uint64_t* ptr)
{
    OE_TEST(s.count == 7);
    OE_TEST(s.size == 64);
    OE_TEST(s.ptr == ptr);
    OE_TEST(oe_is_outside_enclave(s.ptr, sizeof(uint64_t)));
}

// Assert that the struct is shallow-copied (even though it is passed
// by pointer), such that `s->ptr` is the address of `data[]` in the
// host (also passed via `ptr`).
void deepcopy_shallow(ShallowStruct* s, uint64_t* ptr)
{
    OE_TEST(s->count == 7);
    OE_TEST(s->size == 64);
    OE_TEST(s->ptr == ptr);
    OE_TEST(oe_is_outside_enclave(s->ptr, sizeof(uint64_t)));
}

// Assert that the struct is deep-copied such that `s->ptr` has a copy
// of three elements of `data` in enclave memory.
void deepcopy_count(CountStruct* s)
{
    OE_TEST(s->count == 7);
    OE_TEST(s->size == 64);
    for (size_t i = 0; i < 3; ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, 3 * sizeof(uint64_t)));
}

// Assert that the struct is deep-copied such that `s->ptr` has a copy
// of `s->count` elements of `data` in enclave memory.
void deepcopy_countparam(CountParamStruct* s)
{
    OE_TEST(s->count == 7);
    OE_TEST(s->size == 64);
    for (size_t i = 0; i < s->count; ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, s->count * sizeof(uint64_t)));
    // Modify the member used by the size attribute, which should
    // not affect the value on the caller side.
    s->count = 5;
    // Modify the member not used by the size/count attributes,
    // which should affect the value on the caller side.
    s->size = 200;
}

void deepcopy_countparam_return_large(CountParamStruct* s)
{
    OE_TEST(s->count == 7);
    OE_TEST(s->size == 64);
    for (size_t i = 0; i < s->count; ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, s->count * sizeof(uint64_t)));
    // Set the value to the member used by the count attribute larger
    // than the supplied value. Expect to fail.
    s->count = 100;
    // Modify the member not used by the size/count attributes,
    // which should affect the value on the caller side.
    s->size = 200;
}

void deepcopy_size(SizeStruct* s)
{
    OE_TEST(s->count == 7);
    OE_TEST(s->size == 64);
    for (size_t i = 0; i < 2; ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, 16));
}

void deepcopy_countsize(CountSizeStruct* s)
{
    OE_TEST(s->count == 7);
    OE_TEST(s->size == 64);
    for (size_t i = 0; i < 3; ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, 24));
    // Modify the member not used by the size/count attributes,
    // which should affect the value on the caller side.
    s->count = 5;
    s->size = 32;
}

void deepcopy_countsize_return_large(CountSizeStruct* s)
{
    OE_TEST(s->count == 7);
    OE_TEST(s->size == 64);
    for (size_t i = 0; i < 3; ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, 24));
    // Modify the member not used by the size/count attributes,
    // which should affect the value on the caller side.
    // Setting larger value is allowed in this case.
    s->count = 100;
    s->size = 200;
}

// Assert that the struct is deep-copied such that `s->ptr` has a copy
// of `s->size` bytes of `data` in enclave memory.
void deepcopy_sizeparam(SizeParamStruct* s)
{
    OE_TEST(s->count == 7);
    OE_TEST(s->size == 64);
    for (size_t i = 0; i < s->size / sizeof(uint64_t); ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, s->size));
    // Modify the member not used by the size/count attributes,
    // which should affect the value on the caller side.
    s->count = 100;
    // Modify the member used by the size attribute, which should
    // not affect the value on the caller side.
    s->size = 32;
}

void deepcopy_sizeparam_return_large(SizeParamStruct* s)
{
    OE_TEST(s->count == 7);
    OE_TEST(s->size == 64);
    for (size_t i = 0; i < s->size / sizeof(uint64_t); ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, s->size));
    // Modify the member not used by the size/count attributes,
    // which should affect the value on the caller side.
    s->count = 100;
    // Set the value to the member used by the size attribute larger
    // than the supplied value. Expect to fail.
    s->size = 200;
}

// Assert that the struct is deep-copied such that `s->ptr` has a copy
// of `s->count * s->size` bytes of `data` in enclave memory.
void deepcopy_countsizeparam(CountSizeParamStruct* s)
{
    OE_TEST(s->count == 8);
    OE_TEST(s->size == 4);
    for (size_t i = 0; i < (s->count * s->size) / sizeof(uint64_t); ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, s->count * s->size));
    // Modify the member used by size/count attributes, which should
    // not affect the value on the caller side.
    s->count = 4;
    s->size = 2;
}

void deepcopy_countsizeparam_return_large(CountSizeParamStruct* s)
{
    OE_TEST(s->count == 8);
    OE_TEST(s->size == 4);
    for (size_t i = 0; i < (s->count * s->size) / sizeof(uint64_t); ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, s->count * s->size));
    // Set the value to the member used by the size attribute larger
    // than the supplied value. Expect to fail.
    s->count = 100;
    s->size = 200;
}

// Assert that the struct is deep-copied such that `s->ptr` has a copy
// of `s->count * s->size` bytes of `data` in enclave memory, not just
// `s->count` copies.
void deepcopy_countsizeparam_size(CountSizeParamStruct* s)
{
    OE_TEST(s->count == 1);
    OE_TEST(s->size == (4 * sizeof(uint64_t)));
    for (size_t i = 0; i < 4; ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, (4 * sizeof(uint64_t))));
}

// Assert that the struct is deep-copied such that `s->ptr` has a copy
// of `s->count * s->size` bytes of `data` in enclave memory, not just
// `s->size` bytes.
void deepcopy_countsizeparam_count(CountSizeParamStruct* s)
{
    OE_TEST(s->count == 4);
    OE_TEST(s->size == sizeof(uint64_t));
    for (size_t i = 0; i < 4; ++i)
        OE_TEST(s->ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s->ptr, (4 * sizeof(uint64_t))));
}

// Assert that the struct array is deep-copied such that each
// element's `ptr` has a copy of its `count` elements of `data` in
// enclave memory.
void deepcopy_countparamarray(CountParamStruct* s)
{
    OE_TEST(s[0].count == 7);
    OE_TEST(s[0].size == 64);
    for (size_t i = 0; i < s[0].count; ++i)
        OE_TEST(s[0].ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s[0].ptr, s[0].count * sizeof(uint64_t)));

    OE_TEST(s[1].count == 3);
    OE_TEST(s[1].size == 32);
    for (size_t i = 0; i < s[1].count; ++i)
        OE_TEST(s[1].ptr[i] == data[4 + i]);
    OE_TEST(oe_is_within_enclave(s[1].ptr, s[1].count * sizeof(uint64_t)));
}

// Assert that the struct array is deep-copied such that each
// element's `ptr` has a copy of its `size` bytes of `data` in enclave
// memory.
void deepcopy_sizeparamarray(SizeParamStruct* s)
{
    OE_TEST(s[0].count == 7);
    OE_TEST(s[0].size == 64);
    for (size_t i = 0; i < s[0].size / sizeof(uint64_t); ++i)
        OE_TEST(s[0].ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s[0].ptr, s[0].size));

    OE_TEST(s[1].count == 3);
    OE_TEST(s[1].size == 32);
    for (size_t i = 0; i < s[1].size / sizeof(uint64_t); ++i)
        OE_TEST(s[1].ptr[i] == data[4 + i]);
    OE_TEST(oe_is_within_enclave(s[1].ptr, s[1].size));
}

// Assert that the struct array is deep-copied such that each
// element's `ptr` has a copy of its `count * size` bytes of `data` in
// enclave memory.
void deepcopy_countsizeparamarray(CountSizeParamStruct* s)
{
    OE_TEST(s[0].count == 8);
    OE_TEST(s[0].size == 4);
    for (size_t i = 0; i < (s[0].count * s[0].size) / sizeof(uint64_t); ++i)
        OE_TEST(s[0].ptr[i] == data[i]);
    OE_TEST(oe_is_within_enclave(s[0].ptr, s[0].count * s[0].size));

    OE_TEST(s[1].count == 3);
    OE_TEST(s[1].size == 8);
    for (size_t i = 0; i < (s[1].count * s[1].size) / sizeof(uint64_t); ++i)
        OE_TEST(s[1].ptr[i] == data[4 + i]);
    OE_TEST(oe_is_within_enclave(s[1].ptr, s[1].count * s[1].size));
}

void deepcopy_nested(NestedStruct* n)
{
    OE_TEST(oe_is_within_enclave(n, sizeof(NestedStruct)));

    OE_TEST(n->plain_int == 13);

    OE_TEST(oe_is_within_enclave(n->array_of_int, 4 * sizeof(int)));
    for (int i = 0; i < 4; ++i)
        OE_TEST(n->array_of_int[i] == i);

    OE_TEST(oe_is_outside_enclave(n->shallow_struct, sizeof(ShallowStruct)));

    OE_TEST(oe_is_within_enclave(n->array_of_struct, 3 * sizeof(CountStruct)));
    for (size_t i = 0; i < 3; ++i)
        deepcopy_count(&(n->array_of_struct[i]));
}

void deepcopy_super_nested(SuperNestedStruct* s, size_t n)
{
    OE_TEST(oe_is_within_enclave(s, n * sizeof(SuperNestedStruct)));
    // This test exists to check that the produced size of `_ptrs` is
    // `n * (1 + 2 * (1 + 1 + 3))`.
    OE_TEST(oe_is_within_enclave(
        s[0].more_structs[0].array_of_struct, 3 * sizeof(CountStruct)));
    OE_TEST(oe_is_outside_enclave(
        s[0].more_structs[0].shallow_struct, sizeof(ShallowStruct)));
}

void deepcopy_null(CountStruct* s)
{
    OE_UNUSED(s);
}

void deepcopy_in(CountStruct* s)
{
    // Assert that it was copied in correctly.
    deepcopy_count(s);
    // Cause it to copy out incorrectly.
    for (size_t i = 0; i < 3; ++i)
        s->ptr[i] = i;
}

void deepcopy_inout_count(CountStruct* s)
{
    OE_TEST(s->count == 5);
    OE_TEST(s->size == 6);
    for (size_t i = 0; i < 3; ++i)
        OE_TEST(s->ptr[i] == 7);
    s->count = 7;
    s->size = 64;
    for (size_t i = 0; i < 3; ++i)
        s->ptr[i] = data[i];
}

void deepcopy_iovec(IOVEC* iov, size_t n)
{
    OE_TEST(!(n && !iov));
    OE_TEST(n == 2);

    for (size_t i = 0; i < n; i++)
    {
        char* str = (char*)iov[i].base;
        size_t len = iov[i].len;

        switch (i)
        {
            case 0:
                OE_TEST(len == 8);
                OE_TEST(oe_strcmp(str, "red") == 0);
                memcpy(str, "0000000", 8);
                break;
            case 1:
                OE_TEST(len == 0);
                OE_TEST(str == NULL);
                break;
            default:
                OE_TEST(false);
                break;
        }
    }
}

void deepcopy_countparam_out(CountParamStruct* s)
{
    if (!s)
        return;
    OE_TEST(s->count == 0);
    OE_TEST(s->size == 0);
    OE_TEST(s->ptr == NULL);
    s->count = 5;
    s->size = 200;
    s->ptr = (uint64_t*)malloc(s->count * sizeof(uint64_t));
    for (size_t i = 0; i < 5; ++i)
        s->ptr[i] = data[i];
}

void deepcopy_countparamarray_out(CountParamStruct* s)
{
    OE_TEST(s != NULL);
    OE_TEST(s->count == 0);
    OE_TEST(s->size == 0);
    OE_TEST(s->ptr == NULL);
    s[0].count = 5;
    s[0].size = 64;
    s[0].ptr = (uint64_t*)malloc(s[0].count * sizeof(uint64_t));
    for (size_t i = 0; i < s[0].count; ++i)
        s[0].ptr[i] = data[i];

    s[1].count = 4;
    s[1].size = 32;
    s[1].ptr = (uint64_t*)malloc(s[1].count * sizeof(uint64_t));
    for (size_t i = 0; i < s[1].count; ++i)
        s[1].ptr[i] = data[i];
}

void deepcopy_countparamarray_partial_out(CountParamStruct* s)
{
    OE_TEST(s != NULL);
    OE_TEST(s->count == 0);
    OE_TEST(s->size == 0);
    OE_TEST(s->ptr == NULL);
    s[0].count = 5;
    s[0].size = 64;
    s[0].ptr = (uint64_t*)malloc(s[0].count * sizeof(uint64_t));
    for (size_t i = 0; i < s[0].count; ++i)
        s[0].ptr[i] = data[i];

    s[1].count = 0;
    s[1].size = 32;
    s[1].ptr = NULL;
}

void deepcopy_sizeparam_out(SizeParamStruct* s)
{
    OE_TEST(s != NULL);
    OE_TEST(s->count == 0);
    OE_TEST(s->size == 0);
    OE_TEST(s->ptr == NULL);
    s->count = 100;
    s->size = 5 * sizeof(uint64_t);
    s->ptr = (uint64_t*)malloc(s->size);
    for (size_t i = 0; i < 5; ++i)
        s->ptr[i] = data[i];
}

void deepcopy_countsizeparam_out(CountSizeParamStruct* s)
{
    OE_TEST(s != NULL);
    OE_TEST(s->count == 0);
    OE_TEST(s->size == 0);
    OE_TEST(s->ptr == NULL);
    s->count = 5;
    s->size = sizeof(uint64_t);
    s->ptr = (uint64_t*)malloc(s->size * s->count);
    for (size_t i = 0; i < 5; ++i)
        s->ptr[i] = data[i];
}

void deepcopy_countsize_out(CountSizeStruct* s)
{
    OE_TEST(s != NULL);
    OE_TEST(s->count == 0);
    OE_TEST(s->size == 0);
    OE_TEST(s->ptr == NULL);
    s->ptr = (uint64_t*)malloc(2 * 12);
    for (size_t i = 0; i < 3; ++i)
        s->ptr[i] = data[i];
    s->count = 100;
    s->size = 200;
}

void deepcopy_nested_countparam_out(CountParamNestedStruct* n)
{
    OE_TEST(n != NULL);
    OE_TEST(n->num == 0);
    OE_TEST(n->array_of_struct == NULL);
    n->num = 5;
    n->array_of_struct =
        (CountParamStruct*)malloc(n->num * sizeof(CountParamStruct));
    for (size_t i = 0; i < n->num; i++)
    {
        CountParamStruct* s = &n->array_of_struct[i];
        s->count = 10;
        s->size = i;
        s->ptr = (uint64_t*)malloc(s->count * sizeof(uint64_t));
        for (size_t j = 0; j < s->count; j++)
            s->ptr[j] = i;
    }
}

void deepcopy_nested_out(NestedStruct* n)
{
    OE_TEST(n != NULL);
    OE_TEST(n->plain_int == 0);
    OE_TEST(n->array_of_int == NULL);
    OE_TEST(n->shallow_struct == NULL);
    OE_TEST(n->array_of_struct == NULL);
    n->plain_int = 100;
    n->array_of_int = (int*)malloc(4 * sizeof(int));
    for (int i = 0; i < 4; i++)
        n->array_of_int[i] = i;
    n->shallow_struct = NULL;
    n->array_of_struct = (CountStruct*)malloc(3 * sizeof(CountSizeStruct));
    for (int i = 0; i < 3; i++)
    {
        n->array_of_struct[i].ptr = (uint64_t*)malloc(3 * sizeof(uint64_t));
        n->array_of_struct[i].count = 100;
        n->array_of_struct[i].size = 200;
        for (int j = 0; j < 3; j++)
            n->array_of_struct[i].ptr[j] = data[j];
    }
}

void deepcopy_multiple_nested_out(MultipleNestedStruct* n)
{
    OE_TEST(n != NULL);
    OE_TEST(n->num_1 == 0);
    OE_TEST(n->array_of_struct_1 == NULL);
    OE_TEST(n->num_2 == 0);
    OE_TEST(n->array_of_struct_2 == NULL);
    OE_TEST(n->num_3 == 0);
    OE_TEST(n->array_of_struct_3 == NULL);
    OE_TEST(n->num_4 == 0);
    OE_TEST(n->array_of_struct_4 == NULL);

    n->num_1 = 5;
    n->array_of_struct_1 =
        (CountParamStruct*)malloc(n->num_1 * sizeof(CountParamStruct));
    for (size_t i = 0; i < n->num_1; i++)
    {
        CountParamStruct* s = &n->array_of_struct_1[i];
        s->count = 10;
        s->size = i;
        s->ptr = (uint64_t*)malloc(s->count * sizeof(uint64_t));
        for (size_t j = 0; j < s->count; j++)
            s->ptr[j] = i;
    }
    n->num_2 = 6;
    n->array_of_struct_2 =
        (SizeParamStruct*)malloc(n->num_2 * sizeof(SizeParamStruct));
    for (size_t i = 0; i < n->num_2; i++)
    {
        SizeParamStruct* s = &n->array_of_struct_2[i];
        s->count = i;
        s->size = 15 * sizeof(uint64_t);
        s->ptr = (uint64_t*)malloc(s->size);
        for (size_t j = 0; j < 15; j++)
            s->ptr[j] = i;
    }

    n->num_3 = 7;
    n->array_of_struct_3 =
        (CountSizeParamStruct*)malloc(n->num_3 * sizeof(CountSizeParamStruct));
    for (size_t i = 0; i < n->num_3; i++)
    {
        CountSizeParamStruct* s = &n->array_of_struct_3[i];
        s->count = 20;
        s->size = sizeof(uint64_t);
        s->ptr = (uint64_t*)malloc(s->count * s->size);
        for (size_t j = 0; j < s->count; j++)
            s->ptr[j] = i;
    }

    n->num_4 = 3;
    n->array_of_struct_4 = (CountParamNestedStruct*)malloc(
        n->num_4 * sizeof(CountParamNestedStruct));
    for (size_t i = 0; i < n->num_4; i++)
    {
        CountParamNestedStruct* s = &n->array_of_struct_4[i];
        s->num = 4;
        s->array_of_struct =
            (CountParamStruct*)malloc(s->num * sizeof(CountParamStruct));
        for (size_t j = 0; j < s->num; j++)
        {
            CountParamStruct* m = &s->array_of_struct[j];
            m->count = 25;
            m->size = j;
            m->ptr = (uint64_t*)malloc(m->count * sizeof(uint64_t));
            for (size_t k = 0; k < m->count; k++)
                m->ptr[k] = j;
        }
    }
}

void deepcopy_multiple_nested_partial_out(MultipleNestedStruct* n)
{
    OE_TEST(n != NULL);
    OE_TEST(n->num_1 == 0);
    OE_TEST(n->array_of_struct_1 == NULL);
    OE_TEST(n->num_2 == 0);
    OE_TEST(n->array_of_struct_2 == NULL);
    OE_TEST(n->num_3 == 0);
    OE_TEST(n->array_of_struct_3 == NULL);
    OE_TEST(n->num_4 == 0);
    OE_TEST(n->array_of_struct_4 == NULL);

    n->num_1 = 5;
    n->array_of_struct_1 =
        (CountParamStruct*)malloc(n->num_1 * sizeof(CountParamStruct));
    for (size_t i = 0; i < n->num_1; i++)
    {
        CountParamStruct* s = &n->array_of_struct_1[i];
        s->count = 10;
        s->size = i;
        s->ptr = (uint64_t*)malloc(s->count * sizeof(uint64_t));
        for (size_t j = 0; j < s->count; j++)
            s->ptr[j] = i;
    }

    n->num_2 = 6;
    n->array_of_struct_2 = NULL;

    n->num_3 = 7;
    n->array_of_struct_3 =
        (CountSizeParamStruct*)malloc(n->num_3 * sizeof(CountSizeParamStruct));
    for (size_t i = 0; i < n->num_3; i++)
    {
        CountSizeParamStruct* s = &n->array_of_struct_3[i];
        if (i == 3)
        {
            s->count = 10;
            s->size = 5;
            s->ptr = NULL;
            continue;
        }
        s->count = 20;
        s->size = sizeof(uint64_t);
        s->ptr = (uint64_t*)malloc(s->count * s->size);
        for (size_t j = 0; j < s->count; j++)
            s->ptr[j] = i;
    }

    n->num_4 = 3;
    n->array_of_struct_4 = (CountParamNestedStruct*)malloc(
        n->num_4 * sizeof(CountParamNestedStruct));
    for (size_t i = 0; i < n->num_4; i++)
    {
        CountParamNestedStruct* s = &n->array_of_struct_4[i];
        if (i == 2)
        {
            s->num = 2;
            s->array_of_struct = NULL;
            continue;
        }
        s->num = 4;
        s->array_of_struct =
            (CountParamStruct*)malloc(s->num * sizeof(CountParamStruct));
        for (size_t j = 0; j < s->num; j++)
        {
            CountParamStruct* m = &s->array_of_struct[j];
            if (j == 1)
            {
                m->count = 30;
                m->size = 15;
                m->ptr = NULL;
                continue;
            }
            m->count = 25;
            m->size = j;
            m->ptr = (uint64_t*)malloc(m->count * sizeof(uint64_t));
            for (size_t k = 0; k < m->count; k++)
                m->ptr[k] = j;
        }
    }
}

static void set_sizeparam(
    SizeParamStruct* s,
    size_t count,
    size_t size,
    int pattern,
    bool in_enclave)
{
    s->count = count;
    s->size = size;
    if (in_enclave)
        s->ptr = (uint64_t*)malloc(size);
    else
        s->ptr = (uint64_t*)oe_host_malloc(size);
    memset(s->ptr, pattern, size);
}

static void check_sizeparam(
    SizeParamStruct* s,
    size_t count,
    size_t size,
    int pattern)
{
    OE_TEST(s->count == count);
    OE_TEST(s->size == size);
    for (size_t i = 0; i < size; i++)
        OE_TEST(((char*)s->ptr)[i] == pattern);
}

void deepcopy_mix(
    SizeParamStruct* s_in,
    SizeParamStruct* s_inout,
    SizeParamStruct* s_out,
    SizeParamStruct* s_user_check,
    SizeParamStruct* s_out_2)
{
    OE_TEST(s_in->count == 10);
    OE_TEST(s_in->size == 10);
    for (int i = 0; i < 10; i++)
        OE_TEST(((char*)s_in->ptr)[i] == 'A');

    OE_TEST(s_inout->count == 20);
    OE_TEST(s_inout->size == 20);
    for (int i = 0; i < 20; i++)
        OE_TEST(((char*)s_inout->ptr)[i] == 'B');

    s_inout->count = 10;
    /* Setting the size to an inout struct should not affect the value on the
     * host. */
    s_inout->size = 10;
    memset(s_inout->ptr, 'C', 20);

    OE_TEST(s_out != NULL);
    OE_TEST(s_out->count == 0);
    OE_TEST(s_out->size == 0);
    OE_TEST(s_out->ptr == 0);
    set_sizeparam(s_out, 30, 30, 'D', true);
    set_sizeparam(s_user_check, 40, 40, 'E', false);
    OE_TEST(oe_is_outside_enclave(s_user_check, 40));
    OE_TEST(s_out_2 != NULL);
    OE_TEST(s_out_2->count == 0);
    OE_TEST(s_out_2->size == 0);
    OE_TEST(s_out_2->ptr == 0);
    set_sizeparam(s_out_2, 50, 50, 'F', true);
}

template <typename T>
void test_struct(const T& s, size_t size = 8, size_t offset = 0)
{
    for (size_t i = 0; i < size; ++i)
        OE_TEST(s.ptr[i] == data[offset + i]);
}

template <typename T>
T init_struct()
{
    T s = T{7ULL, 64ULL, data};
    test_struct(s);
    return s;
}

void test_deepcopy_ocalls()
{
    {
        auto s = init_struct<CountParamStruct>();
        OE_TEST(ocall_deepcopy_countparam(&s) == OE_OK);
        // The members used by size/count attributes are expected to
        // be consistent even if the callee modified them.
        OE_TEST(s.count == 7);
        // The members not used by size/count attributes are expected to
        // match the value set by the callee.
        OE_TEST(s.size == 200);
        test_struct(s, s.count);
    }

    {
        auto s = init_struct<SizeParamStruct>();
        OE_TEST(ocall_deepcopy_sizeparam(&s) == OE_OK);
        // The members used by size/count attributes are expected to
        // be consistent even if the callee modified them.
        OE_TEST(s.size == 64);
        // The members not used by size/count attributes are expected to
        // match the value set by the callee.
        OE_TEST(s.count == 100);
        test_struct(s, s.size / sizeof(uint64_t));
    }

    {
        auto s = init_struct<CountSizeParamStruct>();
        s.count = 8;
        s.size = 4;
        OE_TEST(ocall_deepcopy_countsizeparam(&s) == OE_OK);
        // The members used by size/count attributes are expected to
        // be consistent even if the callee modified them.
        OE_TEST(s.count == 8);
        OE_TEST(s.size == 4);
        test_struct(s, (s.count * s.size) / sizeof(uint64_t));
    }

    {
        auto s = init_struct<CountSizeStruct>();
        OE_TEST(ocall_deepcopy_countsize(&s) == OE_OK);
        test_struct(s, 3);
        // The members not used by size/count attributes are expected to
        // match the value set by the callee.
        OE_TEST(s.count == 5);
        OE_TEST(s.size == 32);
    }

    {
        auto s = init_struct<CountParamStruct>();
        OE_TEST(ocall_deepcopy_countparam_return_large(&s) == OE_FAILURE);
    }

    {
        auto s = init_struct<SizeParamStruct>();
        OE_TEST(ocall_deepcopy_sizeparam_return_large(&s) == OE_FAILURE);
    }

    {
        auto s = init_struct<CountSizeParamStruct>();
        s.count = 8;
        s.size = 4;
        OE_TEST(ocall_deepcopy_countsizeparam_return_large(&s) == OE_FAILURE);
    }

    {
        auto s = init_struct<CountSizeStruct>();
        OE_TEST(ocall_deepcopy_countsize_return_large(&s) == OE_OK);
        test_struct(s, 3);
        // The members not used by size/count attributes are expected to
        // match the value set by the callee.
        OE_TEST(s.count == 100);
        OE_TEST(s.size == 200);
    }

    {
        CountParamStruct s;
        memset(&s, 0, sizeof(CountParamStruct));
        OE_TEST(ocall_deepcopy_countparam_out(&s) == OE_OK);
        test_struct(s, 5);
        OE_TEST(s.count == 5);
        OE_TEST(s.size == 200);
        free(s.ptr);
    }

    {
        OE_TEST(ocall_deepcopy_countparam_out(NULL) == OE_OK);
    }

    {
        CountParamStruct s[2];
        memset(s, 0, sizeof(CountParamStruct) * 2);
        OE_TEST(ocall_deepcopy_countparamarray_out(s) == OE_OK);
        test_struct(s[0], 5);
        OE_TEST(s[0].count == 5);
        OE_TEST(s[0].size == 64);
        test_struct(s[1], 4);
        OE_TEST(s[1].count == 4);
        OE_TEST(s[1].size == 32);
        for (int i = 0; i < 2; i++)
            free(s[i].ptr);
    }

    {
        CountParamStruct s[2];
        memset(s, 0, sizeof(CountParamStruct) * 2);
        OE_TEST(ocall_deepcopy_countparamarray_partial_out(s) == OE_OK);
        test_struct(s[0], 5);
        OE_TEST(s[0].count == 5);
        OE_TEST(s[0].size == 64);
        OE_TEST(s[1].count == 0);
        OE_TEST(s[1].size == 32);
        OE_TEST(s[1].ptr == NULL);
        for (int i = 0; i < 1; i++)
            free(s[i].ptr);
    }

    {
        SizeParamStruct s;
        memset(&s, 0, sizeof(SizeParamStruct));
        OE_TEST(ocall_deepcopy_sizeparam_out(&s) == OE_OK);
        test_struct(s, 5);
        OE_TEST(s.count == 100);
        OE_TEST(s.size == 5 * sizeof(uint64_t));
        free(s.ptr);
    }

    {
        CountSizeParamStruct s;
        memset(&s, 0, sizeof(CountSizeParamStruct));
        OE_TEST(ocall_deepcopy_countsizeparam_out(&s) == OE_OK);
        test_struct(s, 5);
        OE_TEST(s.count == 5);
        OE_TEST(s.size == sizeof(uint64_t));
        free(s.ptr);
    }

    {
        CountSizeStruct s;
        memset(&s, 0, sizeof(CountSizeStruct));
        OE_TEST(ocall_deepcopy_countsize_out(&s) == OE_OK);
        test_struct(s, 3);
        OE_TEST(s.count == 100);
        OE_TEST(s.size == 200);
        free(s.ptr);
    }

    {
        CountParamNestedStruct n;
        memset(&n, 0, sizeof(CountParamNestedStruct));
        OE_TEST(ocall_deepcopy_nested_countparam_out(&n) == OE_OK);
        OE_TEST(n.num == 5);
        for (size_t i = 0; i < n.num; i++)
        {
            CountParamStruct* s = &n.array_of_struct[i];
            OE_TEST(s->count == 10);
            OE_TEST(s->size == i);
            for (size_t j = 0; j < s->count; j++)
            {
                OE_TEST(s->ptr[j] == i);
            }
        }
        if (n.array_of_struct)
        {
            for (size_t i = 0; i < n.num; i++)
                free(n.array_of_struct[i].ptr);
            free(n.array_of_struct);
        }
    }

    {
        NestedStruct n;
        memset(&n, 0, sizeof(NestedStruct));
        OE_TEST(ocall_deepcopy_nested_out(&n) == OE_OK);
        OE_TEST(n.plain_int == 100);
        for (int i = 0; i < 4; i++)
            OE_TEST(n.array_of_int[i] == i);
        OE_TEST(n.shallow_struct == NULL);
        for (int i = 0; i < 3; i++)
        {
            OE_TEST(n.array_of_struct[i].count == 100);
            OE_TEST(n.array_of_struct[i].size == 200);
            test_struct(n.array_of_struct[i], 3);
        }
        free(n.array_of_int);
        for (int i = 0; i < 3; i++)
            free(n.array_of_struct[i].ptr);
        free(n.array_of_struct);
    }

    {
        MultipleNestedStruct n;
        memset(&n, 0, sizeof(MultipleNestedStruct));
        OE_TEST(ocall_deepcopy_multiple_nested_out(&n) == OE_OK);
        OE_TEST(n.num_1 == 5);
        for (size_t i = 0; i < n.num_1; i++)
        {
            CountParamStruct* s = &n.array_of_struct_1[i];
            OE_TEST(s->count == 10);
            OE_TEST(s->size == i);
            for (size_t j = 0; j < s->count; j++)
            {
                OE_TEST(s->ptr[j] == i);
            }
        }

        OE_TEST(n.num_2 == 6);
        for (size_t i = 0; i < n.num_2; i++)
        {
            SizeParamStruct* s = &n.array_of_struct_2[i];
            OE_TEST(s->count == i);
            OE_TEST(s->size == 15 * sizeof(uint64_t));
            for (size_t j = 0; j < 15; j++)
            {
                OE_TEST(s->ptr[j] == i);
            }
        }

        OE_TEST(n.num_3 == 7);
        for (size_t i = 0; i < n.num_3; i++)
        {
            CountSizeParamStruct* s = &n.array_of_struct_3[i];
            OE_TEST(s->count == 20);
            OE_TEST(s->size == sizeof(uint64_t));
            for (size_t j = 0; j < 20; j++)
            {
                OE_TEST(s->ptr[j] == i);
            }
        }

        OE_TEST(n.num_4 == 3);
        for (size_t i = 0; i < n.num_4; i++)
        {
            CountParamNestedStruct* s = &n.array_of_struct_4[i];
            OE_TEST(s->num == 4);
            for (size_t j = 0; j < s->num; j++)
            {
                CountParamStruct* m = &s->array_of_struct[j];
                OE_TEST(m->count == 25);
                OE_TEST(m->size == j);
                for (size_t k = 0; k < m->count; k++)
                {
                    OE_TEST(m->ptr[k] == j);
                }
            }
        }

        if (n.array_of_struct_1)
        {
            for (size_t i = 0; i < n.num_1; i++)
                free(n.array_of_struct_1[i].ptr);
            free(n.array_of_struct_1);
        }
        if (n.array_of_struct_2)
        {
            for (size_t i = 0; i < n.num_2; i++)
                free(n.array_of_struct_2[i].ptr);
            free(n.array_of_struct_2);
        }
        if (n.array_of_struct_3)
        {
            for (size_t i = 0; i < n.num_3; i++)
                free(n.array_of_struct_3[i].ptr);
            free(n.array_of_struct_3);
        }
        if (n.array_of_struct_4)
        {
            for (size_t i = 0; i < n.num_4; i++)
            {
                if (n.array_of_struct_4[i].array_of_struct)
                {
                    for (size_t j = 0; j < n.array_of_struct_4[i].num; j++)
                        free(n.array_of_struct_4[i].array_of_struct[j].ptr);
                }
                free(n.array_of_struct_4[i].array_of_struct);
            }
            free(n.array_of_struct_4);
        }
    }

    {
        MultipleNestedStruct n;
        memset(&n, 0, sizeof(MultipleNestedStruct));
        OE_TEST(ocall_deepcopy_multiple_nested_partial_out(&n) == OE_OK);
        OE_TEST(n.num_1 == 5);
        for (size_t i = 0; i < n.num_1; i++)
        {
            CountParamStruct* s = &n.array_of_struct_1[i];
            OE_TEST(s->count == 10);
            OE_TEST(s->size == i);
            for (size_t j = 0; j < s->count; j++)
            {
                OE_TEST(s->ptr[j] == i);
            }
        }

        OE_TEST(n.num_2 == 6);
        OE_TEST(n.array_of_struct_2 == NULL);

        OE_TEST(n.num_3 == 7);
        for (size_t i = 0; i < n.num_3; i++)
        {
            CountSizeParamStruct* s = &n.array_of_struct_3[i];
            if (i == 3)
            {
                OE_TEST(s->count == 10);
                OE_TEST(s->size == 5);
                OE_TEST(s->ptr == NULL);
                continue;
            }
            OE_TEST(s->count == 20);
            OE_TEST(s->size == sizeof(uint64_t));
            for (size_t j = 0; j < 20; j++)
            {
                OE_TEST(s->ptr[j] == i);
            }
        }

        OE_TEST(n.num_4 == 3);
        for (size_t i = 0; i < n.num_4; i++)
        {
            CountParamNestedStruct* s = &n.array_of_struct_4[i];
            if (i == 2)
            {
                OE_TEST(s->num == 2);
                OE_TEST(s->array_of_struct == NULL);
                continue;
            }
            OE_TEST(s->num == 4);
            for (size_t j = 0; j < s->num; j++)
            {
                CountParamStruct* m = &s->array_of_struct[j];
                if (j == 1)
                {
                    OE_TEST(m->count == 30);
                    OE_TEST(m->size == 15);
                    OE_TEST(m->ptr == NULL);
                    continue;
                }
                OE_TEST(m->count == 25);
                OE_TEST(m->size == j);
                for (size_t k = 0; k < m->count; k++)
                {
                    OE_TEST(m->ptr[k] == j);
                }
            }
        }

        if (n.array_of_struct_1)
        {
            for (size_t i = 0; i < n.num_1; i++)
                free(n.array_of_struct_1[i].ptr);
            free(n.array_of_struct_1);
        }
        if (n.array_of_struct_2)
        {
            for (size_t i = 0; i < n.num_2; i++)
                free(n.array_of_struct_2[i].ptr);
            free(n.array_of_struct_2);
        }
        if (n.array_of_struct_3)
        {
            for (size_t i = 0; i < n.num_3; i++)
                free(n.array_of_struct_3[i].ptr);
            free(n.array_of_struct_3);
        }
        if (n.array_of_struct_4)
        {
            for (size_t i = 0; i < n.num_4; i++)
            {
                if (n.array_of_struct_4[i].array_of_struct)
                {
                    for (size_t j = 0; j < n.array_of_struct_4[i].num; j++)
                        free(n.array_of_struct_4[i].array_of_struct[j].ptr);
                }
                free(n.array_of_struct_4[i].array_of_struct);
            }
            free(n.array_of_struct_4);
        }
    }

    {
        SizeParamStruct s_in, s_inout, s_out, s_user_check, s_out_2;
        set_sizeparam(&s_in, 10, 10, (int)'A', true);
        set_sizeparam(&s_inout, 20, 20, (int)'B', true);
        OE_TEST(
            ocall_deepcopy_mix(
                &s_in, &s_inout, &s_out, &s_user_check, &s_out_2) == OE_OK);
        check_sizeparam(&s_inout, 10, 20, 'C');
        check_sizeparam(&s_out, 30, 30, 'D');
        check_sizeparam(&s_out_2, 50, 50, 'F');
        free(s_in.ptr);
        free(s_inout.ptr);
        free(s_out.ptr);
        free(s_out_2.ptr);
    }
}
