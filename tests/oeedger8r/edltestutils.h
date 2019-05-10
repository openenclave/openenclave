// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma once

#include <openenclave/bits/defs.h>
#include <stdint.h>
#include <wchar.h>
#include <limits>

// Assert that given arguments are of specified types.
// Results in compile error on type mismatch.
template <typename... Args>
void check_type(Args&...)
{
}

// Check the type of _retval field of a given args type.
template <typename args_type, typename R>
void check_return_type()
{
    args_type args;
    check_type<R>(args._retval);
}

template <std::size_t N>
struct unused
{
    unused(std::size_t i = 0)
    {
        OE_UNUSED(i);
    }
};

// Ensure that the given field does not exist
// in given marshaling struct.
// If the field exists, an ambiguous call compiler
// error will occur.

#define DEFINE_ASSERT_NO_FIELD(fname)                            \
    template <typename S>                                        \
    void assert_no_field_##fname(unused<sizeof(S::fname)> u = 0) \
    {                                                            \
        OE_UNUSED(u);                                            \
    }                                                            \
    template <typename S>                                        \
    void assert_no_field_##fname()                               \
    {                                                            \
    }

DEFINE_ASSERT_NO_FIELD(s_len)
DEFINE_ASSERT_NO_FIELD(_ocall_errno)

template <typename T, std::size_t N, typename U>
inline int array_compare(const T (&a1)[N], U u)
{
    const T* a2 = (const T*)u;
    for (std::size_t i = 0; i < N; ++i)
    {
        if (a1[i] < a2[i])
            return -1;
        else if (a1[i] > a2[i])
            return 1;
    }
    return 0;
}

const wchar_t wchar_t_value = L'\u2126';

extern uint8_t g_enabled[4];

const long long_value = std::numeric_limits<long>::max();
const unsigned long ulong_value = std::numeric_limits<unsigned long>::max();
const long double long_double_value =
    std::numeric_limits<long double>::epsilon();
