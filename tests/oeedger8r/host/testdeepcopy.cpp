// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include <array>
#include "all_u.h"

static uint64_t data[8] = {0x1112131415161718,
                           0x2122232425262728,
                           0x3132333435363738,
                           0x4142434445464748,
                           0x5152535455565758,
                           0x6162636465666768,
                           0x7172737475767778,
                           0x8182838485868788};

template <typename T>
void test_struct(const T& s, size_t size = 8, size_t offset = 0)
{
    for (size_t i = 0; i < size; ++i)
        OE_TEST(s.ptr[i] == data[offset + i]);
}

template <typename T>
void test_structs(const std::array<T, 2>& s)
{
    test_struct(s[0]);
    test_struct(s[1], 4, 4);
}

template <typename T>
T init_struct()
{
    T s = T{7ULL, 64ULL, data};
    test_struct(s);
    return s;
}

template <typename T>
std::array<T, 2> init_structs()
{
    std::array<T, 2> s = {init_struct<T>(), T{3ULL, 32ULL, &data[4]}};
    test_structs(s);
    return s;
}

void test_deepcopy_edl_ecalls(oe_enclave_t* enclave)
{
    {
        // NOTE: These test backwards-compatibility and so should
        // succeed without deep copy support.
        auto s = init_struct<ShallowStruct>();
        OE_TEST(deepcopy_value(enclave, s, data) == OE_OK);
        test_struct(s);
        OE_TEST(deepcopy_shallow(enclave, &s, data) == OE_OK);
        test_struct(s);
    }

    {
        auto s = init_struct<CountStruct>();
        OE_TEST(deepcopy_count(enclave, &s) == OE_OK);
        test_struct(s, 3);
    }

    {
        auto s = init_struct<CountParamStruct>();
        OE_TEST(deepcopy_countparam(enclave, &s) == OE_OK);
        OE_TEST(s.count == 7);
        test_struct(s, s.count);
    }

    {
        auto s = init_struct<SizeParamStruct>();
        OE_TEST(deepcopy_sizeparam(enclave, &s) == OE_OK);
        OE_TEST(s.size == 64);
        test_struct(s, s.size / sizeof(uint64_t));
    }

    {
        auto s = init_struct<CountSizeParamStruct>();
        s.count = 8;
        s.size = 4;
        OE_TEST(deepcopy_countsizeparam(enclave, &s) == OE_OK);
        OE_TEST(s.count == 8);
        OE_TEST(s.size == 4);
        test_struct(s, (s.count * s.size) / sizeof(uint64_t));
    }

    {
        auto s = init_struct<CountSizeParamStruct>();
        s.count = 1;
        s.size = 4 * sizeof(uint64_t);
        OE_TEST(deepcopy_countsizeparam_size(enclave, &s) == OE_OK);
        OE_TEST(s.count == 1);
        OE_TEST(s.size == 4 * sizeof(uint64_t));
        test_struct(s, 4);
    }

    {
        auto s = init_struct<CountSizeParamStruct>();
        s.count = 4;
        s.size = sizeof(uint64_t);
        OE_TEST(deepcopy_countsizeparam_count(enclave, &s) == OE_OK);
        OE_TEST(s.count == 4);
        OE_TEST(s.size == sizeof(uint64_t));
        test_struct(s, 4);
    }

    {
        auto s = init_structs<CountParamStruct>();
        OE_TEST(deepcopy_countparamarray(enclave, s.data()) == OE_OK);
        test_struct(s[0], 7);
        test_struct(s[1], 3, 4);
    }

    {
        auto s = init_structs<SizeParamStruct>();
        OE_TEST(deepcopy_sizeparamarray(enclave, s.data()) == OE_OK);
        test_struct(s[0], s[0].size / sizeof(uint64_t));
        test_struct(s[1], s[1].size / sizeof(uint64_t), 4);
    }

    {
        auto s = init_structs<CountSizeParamStruct>();
        s[0].count = 8;
        s[0].size = 4;
        s[1].count = 3;
        s[1].size = 8;
        OE_TEST(deepcopy_countsizeparamarray(enclave, s.data()) == OE_OK);
        test_struct(s[0], (s[0].count * s[0].size) / sizeof(uint64_t));
        test_struct(s[1], (s[1].count * s[1].size) / sizeof(uint64_t), 4);
    }

    {
        auto s = init_struct<CountStruct>();
        int ints[]{0, 1, 2, 3};
        ShallowStruct shallow{1, 8, nullptr};
        CountStruct counts[]{s, s, s};
        NestedStruct n{13, ints, &shallow, counts};
        NestedStruct p{7, ints, &shallow, counts};
        NestedStruct ns[]{p, n};
        SuperNestedStruct u[]{{ns}, {ns}};

        OE_TEST(deepcopy_super_nested(enclave, u, OE_COUNTOF(u)) == OE_OK);
        OE_TEST(deepcopy_nested(enclave, &n) == OE_OK);

        for (size_t i = 0; i < 4; ++i)
            OE_TEST(n.array_of_int[i] == static_cast<int>(i));

        OE_TEST(n.shallow_struct == &shallow);
        OE_TEST(n.array_of_struct == counts);

        for (size_t i = 0; i < 3; ++i)
            for (size_t j = 0; j < 8; ++j)
                OE_TEST(n.array_of_struct[i].ptr[j] == data[j]);
    }

    {
        OE_TEST(deepcopy_null(enclave, nullptr) == OE_OK);
    }

    {
        CountStruct s{7, 64, nullptr};
        OE_TEST(deepcopy_null(enclave, &s) == OE_OK);
        OE_TEST(s.ptr == nullptr);
    }

    {
        CountStruct s{};
        uint64_t p[3] = {0, 0, 0};
        s.ptr = p;
        OE_TEST(deepcopy_out_count(enclave, &s) == OE_OK);
        OE_TEST(s.count == 7);
        OE_TEST(s.size == 64);
        test_struct(s, 3);
    }

    {
        IOVEC iov[2];
        char buf0[8] = "red";

        iov[0].base = (void*)buf0;
        iov[0].len = sizeof(buf0);
        iov[1].base = NULL;
        iov[1].len = 0;

        OE_TEST(deepcopy_iovec(enclave, iov, OE_COUNTOF(iov)) == OE_OK);
        OE_TEST(memcmp(buf0, "0000000", 8) == 0);
    }

    printf("=== test_deepcopy_edl_ecalls passed\n");
}
