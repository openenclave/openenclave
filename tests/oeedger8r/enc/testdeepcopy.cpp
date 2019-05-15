// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
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
}
