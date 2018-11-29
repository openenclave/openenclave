// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <algorithm>
#include "all_t.h"

template <typename T, typename F>
static void test_ocall_pointer_fun(F ocall_pointer_fun)
{
    // 1 element arrays.
    T p1[1] = {1}, p2[1] = {1}, p3[1] = {1};

    // Arrays declared static to avoid blowing up the stack.

    // 16 element arrays.
    T p4[16], p5[16], p6[16];
    for (size_t i = 0; i < 16; ++i)
        p4[i] = p5[i] = p6[i] = i + 1;

    static_assert((80 / sizeof(T)) * sizeof(T) == 80, "invalid size");
    // arrays with size = 80 bytes.
    const size_t count = 80 / sizeof(T);
    T p7[count], p8[count], p9[count];

    for (size_t i = 0; i < count; ++i)
        p7[i] = p8[i] = p9[i] = i + 1;

    T p10[16];
    for (size_t i = 0; i < 16; ++i)
        p10[i] = i + 1;

    static T p11[16];
    static T p12[16];
    static T p13[16];
    for (size_t i = 0; i < 16; ++i)
        p11[i] = p12[i] = p13[i] = i + 1;

    static T p14[count];
    static T p15[count];
    static T p16[count];
    for (size_t i = 0; i < count; ++i)
        p14[i] = p15[i] = p16[i] = i + 1;

    int pcount = 16;
    int psize = 80;

    T* ret = NULL;
    OE_TEST(
        ocall_pointer_fun(
            &ret,
            p1,
            p2,
            p3,
            p4,
            p5,
            p6,
            p7,
            p8,
            p9,
            p10,
            p11,
            p12,
            p13,
            p14,
            p15,
            p16,
            pcount,
            psize) == OE_OK);
    {
        // p1 is not modified
        OE_TEST(p1[0] == 1);

        // p2, p3 are modified.
        OE_TEST(p2[0] == 2);
        OE_TEST(p3[0] == 2);

        // p5 is reversed.
        T exp[] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
        OE_TEST(array_compare(exp, p5) == 0);

        // p6 is initialized
        for (size_t i = 0; i < 16; ++i)
            OE_TEST(p6[i] == (T)i + 1);

        // p8 is has been reversed.
        for (size_t i = 0; i < count; ++i)
            OE_TEST(p8[i] == (T)(count - i));

        // p9 is initialized.
        for (size_t i = 0; i < count; ++i)
            OE_TEST(p9[i] == (T)i + 1);
    }

    // p10 has not been changed.
    for (size_t i = 0; i < 16; ++i)
        OE_TEST(p10[i] == (T)(i + 1));

    // p10 is returned.
    OE_TEST(ret == p10);

    OE_TEST(pcount == 16);
    OE_TEST(psize == 80);
    {
        // p11, p12, p13 specify pcount as the EDL 'count' attribute.

        // p11 is input and should be untouched.
        for (size_t i = 0; i < (size_t)pcount; ++i)
            OE_TEST(p11[i] == (T)(i + 1));

        // p12 is in-out and should be reversed.
        for (size_t i = 0; i < (size_t)pcount; ++i)
            OE_TEST(p12[i] == (T)(pcount - i));

        // p13 is out and should have value pcount.
        for (size_t i = 0; i < (size_t)pcount; ++i)
            OE_TEST(p13[i] == (T)pcount);
    }

    {
        // p14, p15, p16 specify psize as the EDL 'size' attribute.

        // p14 is input and should be untouched.
        for (size_t i = 0; i < (size_t)count; ++i)
            OE_TEST(p14[i] == (T)(i + 1));

        // p15 is in-out and should be reversed.
        for (size_t i = 0; i < (size_t)count; ++i)
            OE_TEST(p15[i] == (T)(count - i));

        // p16 is out and should have value pcount.
        for (size_t i = 0; i < (size_t)count; ++i)
            OE_TEST(p16[i] == (T)psize);
    }

    // Call with nulls.
    OE_TEST(
        ocall_pointer_fun(
            &ret,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            NULL,
            pcount,
            psize) == OE_OK);
}

void test_pointer_edl_ocalls()
{
    test_ocall_pointer_fun<char>(ocall_pointer_char);
    if (g_enabled[TYPE_WCHAR_T])
        test_ocall_pointer_fun<wchar_t>(ocall_pointer_wchar_t);
    test_ocall_pointer_fun<short>(ocall_pointer_short);
    test_ocall_pointer_fun<int>(ocall_pointer_int);
    test_ocall_pointer_fun<float>(ocall_pointer_float);
    test_ocall_pointer_fun<double>(ocall_pointer_double);
    if (g_enabled[TYPE_LONG])
        test_ocall_pointer_fun<long>(ocall_pointer_long);
    test_ocall_pointer_fun<size_t>(ocall_pointer_size_t);
    test_ocall_pointer_fun<unsigned>(ocall_pointer_unsigned);
    test_ocall_pointer_fun<int8_t>(ocall_pointer_int8_t);
    test_ocall_pointer_fun<int16_t>(ocall_pointer_int16_t);
    test_ocall_pointer_fun<int32_t>(ocall_pointer_int32_t);
    test_ocall_pointer_fun<int64_t>(ocall_pointer_int64_t);
    test_ocall_pointer_fun<uint8_t>(ocall_pointer_uint8_t);
    test_ocall_pointer_fun<uint16_t>(ocall_pointer_uint16_t);
    test_ocall_pointer_fun<uint32_t>(ocall_pointer_uint32_t);
    test_ocall_pointer_fun<uint64_t>(ocall_pointer_uint64_t);
    test_ocall_pointer_fun<long long>(ocall_pointer_long_long);
    if (g_enabled[TYPE_LONG_DOUBLE])
        test_ocall_pointer_fun<long double>(ocall_pointer_long_double);
    test_ocall_pointer_fun<unsigned char>(ocall_pointer_unsigned_char);
    test_ocall_pointer_fun<unsigned short>(ocall_pointer_unsigned_short);
    test_ocall_pointer_fun<unsigned int>(ocall_pointer_unsigned_int);
    if (g_enabled[TYPE_UNSIGNED_LONG])
        test_ocall_pointer_fun<unsigned long>(ocall_pointer_unsigned_long);

    OE_TEST(ocall_pointer_assert_all_called() == OE_OK);
    printf("=== test_pointer_edl_ocalls passed\n");
}

template <typename T>
static void reverse(T* arr, size_t len)
{
    for (size_t i = 0; i < len / 2; ++i)
        std::swap(arr[i], arr[len - 1 - i]);
}

static int num_ecalls = 0;
static int num_null_ecalls = 0;

template <typename T>
static T* ecall_pointer_fun_impl(
    T* p1,
    T* p2,
    T* p3,
    T* p4,
    T* p5,
    T* p6,
    T* p7,
    T* p8,
    T* p9,
    T* p10,
    T* p11,
    T* p12,
    T* p13,
    T* p14,
    T* p15,
    T* p16,
    int pcount,
    int psize)
{
    ++num_ecalls;

    // No count or size specified.
    // Treat as count = 1.
    {
        // in
        if (p1)
        {
            OE_TEST(oe_is_within_enclave(p1, sizeof(T)));
            OE_TEST(*p1 == 1);

            // change p1. Should not have any effect on host.
            *p1 = 2;
        }

        // in-out
        if (p2)
        {
            OE_TEST(oe_is_within_enclave(p2, sizeof(T)));
            OE_TEST(*p2 == 1);
            *p2 = 2;
        }

        // out
        if (p3)
        {
            OE_TEST(oe_is_within_enclave(p3, sizeof(T)));
            *p3 = 2;
        }
    }

    // count specified as 16.
    {
        T exp[] = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16};
        // in
        if (p4)
        {
            OE_TEST(oe_is_within_enclave(p4, sizeof(T) * 16));
            OE_TEST(memcmp(p4, exp, sizeof(T) * 16) == 0);

            // change p4. Should not have any effect on host.
            memset(p4, 0, sizeof(T) * 16);
        }

        // in-out
        if (p5)
        {
            OE_TEST(oe_is_within_enclave(p5, sizeof(T) * 16));
            OE_TEST(memcmp(p5, exp, sizeof(T) * 16) == 0);
            reverse(p5, 16);
        }

        // out
        if (p6)
        {
            OE_TEST(oe_is_within_enclave(p5, sizeof(T) * 16));
            memcpy(p6, exp, sizeof(exp));
        }
    }

    // size specified as 80 (lcm of sizeof(double), sizeof(long))
    {
        const size_t count = 80 / sizeof(T);
        T exp[count];
        for (size_t i = 0; i < count; ++i)
            exp[i] = i + 1;

        //
        if (p7)
        {
            OE_TEST(oe_is_within_enclave(p7, 80));
            OE_TEST(array_compare(exp, p7) == 0);

            // change p7. Should not have any effect on host.
            memset(p7, 0, 80);
        }

        // in-out
        if (p8)
        {
            OE_TEST(oe_is_within_enclave(p8, 80));
            OE_TEST(array_compare(exp, p8) == 0);
            reverse(p8, count);
        }

        // out
        if (p9)
        {
            OE_TEST(oe_is_within_enclave(p9, 80));
            memcpy(p9, exp, sizeof(exp));
        }
    }

    // user-check
    if (p10)
    {
        OE_TEST(oe_is_outside_enclave(p10, sizeof(T) * 16));
        reverse(p10, 16);
    }

    {
        // in
        if (p11)
        {
            for (int i = 0; i < pcount; ++i)
                OE_TEST(p11[i] == (T)(i + 1));

            // change p11. Should not have any effect on host.
            memset(p11, 0, sizeof(T) * pcount);
        }

        // in-out
        if (p12)
        {
            for (int i = 0; i < pcount; ++i)
                OE_TEST(p12[i] == (T)(i + 1));
            reverse(p12, pcount);
        }

        // out
        if (p13)
        {
            for (int i = 0; i < pcount; ++i)
                p13[i] = pcount;
        }
    }

    {
        size_t count = psize / sizeof(T);
        // in
        if (p14)
        {
            for (size_t i = 0; i < count; ++i)
                OE_TEST(p14[i] == (T)(i + 1));

            // change p11. Should not have any effect on host.
            memset(p14, 0, sizeof(T) * count);
        }

        // in-out
        if (p15)
        {
            for (size_t i = 0; i < count; ++i)
                OE_TEST(p15[i] == (T)(i + 1));
            reverse(p15, count);
        }

        // out
        if (p16)
        {
            for (size_t i = 0; i < count; ++i)
                p16[i] = psize;
        }
    }

    // For the 2nd test call, all pointers as passed in as null.
    if (!p1 && !p2 && !p3 && !p4 && !p5 && !p6 && !p7 && !p8 && !p9 && !p10 &&
        !p11 && !p12 && !p13 && !p14 && !p15 && !p16)
    {
        ++num_null_ecalls;
    }

    return p10;
}

char* ecall_pointer_char(
    char* p1,
    char* p2,
    char* p3,
    char* p4,
    char* p5,
    char* p6,
    char* p7,
    char* p8,
    char* p9,
    char* p10,
    char* p11,
    char* p12,
    char* p13,
    char* p14,
    char* p15,
    char* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

wchar_t* ecall_pointer_wchar_t(
    wchar_t* p1,
    wchar_t* p2,
    wchar_t* p3,
    wchar_t* p4,
    wchar_t* p5,
    wchar_t* p6,
    wchar_t* p7,
    wchar_t* p8,
    wchar_t* p9,
    wchar_t* p10,
    wchar_t* p11,
    wchar_t* p12,
    wchar_t* p13,
    wchar_t* p14,
    wchar_t* p15,
    wchar_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

short* ecall_pointer_short(
    short* p1,
    short* p2,
    short* p3,
    short* p4,
    short* p5,
    short* p6,
    short* p7,
    short* p8,
    short* p9,
    short* p10,
    short* p11,
    short* p12,
    short* p13,
    short* p14,
    short* p15,
    short* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

int* ecall_pointer_int(
    int* p1,
    int* p2,
    int* p3,
    int* p4,
    int* p5,
    int* p6,
    int* p7,
    int* p8,
    int* p9,
    int* p10,
    int* p11,
    int* p12,
    int* p13,
    int* p14,
    int* p15,
    int* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

float* ecall_pointer_float(
    float* p1,
    float* p2,
    float* p3,
    float* p4,
    float* p5,
    float* p6,
    float* p7,
    float* p8,
    float* p9,
    float* p10,
    float* p11,
    float* p12,
    float* p13,
    float* p14,
    float* p15,
    float* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

double* ecall_pointer_double(
    double* p1,
    double* p2,
    double* p3,
    double* p4,
    double* p5,
    double* p6,
    double* p7,
    double* p8,
    double* p9,
    double* p10,
    double* p11,
    double* p12,
    double* p13,
    double* p14,
    double* p15,
    double* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

long* ecall_pointer_long(
    long* p1,
    long* p2,
    long* p3,
    long* p4,
    long* p5,
    long* p6,
    long* p7,
    long* p8,
    long* p9,
    long* p10,
    long* p11,
    long* p12,
    long* p13,
    long* p14,
    long* p15,
    long* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

size_t* ecall_pointer_size_t(
    size_t* p1,
    size_t* p2,
    size_t* p3,
    size_t* p4,
    size_t* p5,
    size_t* p6,
    size_t* p7,
    size_t* p8,
    size_t* p9,
    size_t* p10,
    size_t* p11,
    size_t* p12,
    size_t* p13,
    size_t* p14,
    size_t* p15,
    size_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

unsigned* ecall_pointer_unsigned(
    unsigned* p1,
    unsigned* p2,
    unsigned* p3,
    unsigned* p4,
    unsigned* p5,
    unsigned* p6,
    unsigned* p7,
    unsigned* p8,
    unsigned* p9,
    unsigned* p10,
    unsigned* p11,
    unsigned* p12,
    unsigned* p13,
    unsigned* p14,
    unsigned* p15,
    unsigned* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

int8_t* ecall_pointer_int8_t(
    int8_t* p1,
    int8_t* p2,
    int8_t* p3,
    int8_t* p4,
    int8_t* p5,
    int8_t* p6,
    int8_t* p7,
    int8_t* p8,
    int8_t* p9,
    int8_t* p10,
    int8_t* p11,
    int8_t* p12,
    int8_t* p13,
    int8_t* p14,
    int8_t* p15,
    int8_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

int16_t* ecall_pointer_int16_t(
    int16_t* p1,
    int16_t* p2,
    int16_t* p3,
    int16_t* p4,
    int16_t* p5,
    int16_t* p6,
    int16_t* p7,
    int16_t* p8,
    int16_t* p9,
    int16_t* p10,
    int16_t* p11,
    int16_t* p12,
    int16_t* p13,
    int16_t* p14,
    int16_t* p15,
    int16_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

int32_t* ecall_pointer_int32_t(
    int32_t* p1,
    int32_t* p2,
    int32_t* p3,
    int32_t* p4,
    int32_t* p5,
    int32_t* p6,
    int32_t* p7,
    int32_t* p8,
    int32_t* p9,
    int32_t* p10,
    int32_t* p11,
    int32_t* p12,
    int32_t* p13,
    int32_t* p14,
    int32_t* p15,
    int32_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

int64_t* ecall_pointer_int64_t(
    int64_t* p1,
    int64_t* p2,
    int64_t* p3,
    int64_t* p4,
    int64_t* p5,
    int64_t* p6,
    int64_t* p7,
    int64_t* p8,
    int64_t* p9,
    int64_t* p10,
    int64_t* p11,
    int64_t* p12,
    int64_t* p13,
    int64_t* p14,
    int64_t* p15,
    int64_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

uint8_t* ecall_pointer_uint8_t(
    uint8_t* p1,
    uint8_t* p2,
    uint8_t* p3,
    uint8_t* p4,
    uint8_t* p5,
    uint8_t* p6,
    uint8_t* p7,
    uint8_t* p8,
    uint8_t* p9,
    uint8_t* p10,
    uint8_t* p11,
    uint8_t* p12,
    uint8_t* p13,
    uint8_t* p14,
    uint8_t* p15,
    uint8_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

uint16_t* ecall_pointer_uint16_t(
    uint16_t* p1,
    uint16_t* p2,
    uint16_t* p3,
    uint16_t* p4,
    uint16_t* p5,
    uint16_t* p6,
    uint16_t* p7,
    uint16_t* p8,
    uint16_t* p9,
    uint16_t* p10,
    uint16_t* p11,
    uint16_t* p12,
    uint16_t* p13,
    uint16_t* p14,
    uint16_t* p15,
    uint16_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

uint32_t* ecall_pointer_uint32_t(
    uint32_t* p1,
    uint32_t* p2,
    uint32_t* p3,
    uint32_t* p4,
    uint32_t* p5,
    uint32_t* p6,
    uint32_t* p7,
    uint32_t* p8,
    uint32_t* p9,
    uint32_t* p10,
    uint32_t* p11,
    uint32_t* p12,
    uint32_t* p13,
    uint32_t* p14,
    uint32_t* p15,
    uint32_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

uint64_t* ecall_pointer_uint64_t(
    uint64_t* p1,
    uint64_t* p2,
    uint64_t* p3,
    uint64_t* p4,
    uint64_t* p5,
    uint64_t* p6,
    uint64_t* p7,
    uint64_t* p8,
    uint64_t* p9,
    uint64_t* p10,
    uint64_t* p11,
    uint64_t* p12,
    uint64_t* p13,
    uint64_t* p14,
    uint64_t* p15,
    uint64_t* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

long long* ecall_pointer_long_long(
    long long* p1,
    long long* p2,
    long long* p3,
    long long* p4,
    long long* p5,
    long long* p6,
    long long* p7,
    long long* p8,
    long long* p9,
    long long* p10,
    long long* p11,
    long long* p12,
    long long* p13,
    long long* p14,
    long long* p15,
    long long* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

long double* ecall_pointer_long_double(
    long double* p1,
    long double* p2,
    long double* p3,
    long double* p4,
    long double* p5,
    long double* p6,
    long double* p7,
    long double* p8,
    long double* p9,
    long double* p10,
    long double* p11,
    long double* p12,
    long double* p13,
    long double* p14,
    long double* p15,
    long double* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

unsigned char* ecall_pointer_unsigned_char(
    unsigned char* p1,
    unsigned char* p2,
    unsigned char* p3,
    unsigned char* p4,
    unsigned char* p5,
    unsigned char* p6,
    unsigned char* p7,
    unsigned char* p8,
    unsigned char* p9,
    unsigned char* p10,
    unsigned char* p11,
    unsigned char* p12,
    unsigned char* p13,
    unsigned char* p14,
    unsigned char* p15,
    unsigned char* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

unsigned short* ecall_pointer_unsigned_short(
    unsigned short* p1,
    unsigned short* p2,
    unsigned short* p3,
    unsigned short* p4,
    unsigned short* p5,
    unsigned short* p6,
    unsigned short* p7,
    unsigned short* p8,
    unsigned short* p9,
    unsigned short* p10,
    unsigned short* p11,
    unsigned short* p12,
    unsigned short* p13,
    unsigned short* p14,
    unsigned short* p15,
    unsigned short* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

unsigned int* ecall_pointer_unsigned_int(
    unsigned int* p1,
    unsigned int* p2,
    unsigned int* p3,
    unsigned int* p4,
    unsigned int* p5,
    unsigned int* p6,
    unsigned int* p7,
    unsigned int* p8,
    unsigned int* p9,
    unsigned int* p10,
    unsigned int* p11,
    unsigned int* p12,
    unsigned int* p13,
    unsigned int* p14,
    unsigned int* p15,
    unsigned int* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

void ecall_pointer_assert_all_called()
{
    // Each of the 19 functions above is called twice.
    // Once with arrays and then with nulls.
    int expected_num_calls = 19 * 2;

    // Account for enabled non-portable types.
    for (size_t i = 0; i < OE_COUNTOF(g_enabled); ++i)
    {
        if (g_enabled[i])
            expected_num_calls += 2;
    }

    OE_TEST(num_ecalls == expected_num_calls);
}

// The following functions exists to make sure there are no
// compile errors when various basic types are used as size,
// count attributes.
void ecall_count_attribute_all_types(
    int* b1,
    int* b2,
    int* b3,
    int* b4,
    int* b5,
    int* b6,
    int* b7,
    int* b8,
    int* b9,
    int* b10,
    int* b11,
    int* b12,
    int* b13,
    int* b14,
    int* b15,
    int* b16,
    int* b17,
    int* b18,
    int* b19,
    int* b20,
    int* b21,
    int* b22,
    int* b23,
    char char_count,
    short short_count,
    int int_count,
    float float_count,
    double double_count,
    long long_count,
    size_t size_t_count,
    unsigned unsigned_count,
    int8_t int8_t_count,
    int16_t int16_t_count,
    int32_t int32_t_count,
    int64_t int64_t_count,
    uint8_t uint8_t_count,
    uint16_t uint16_t_count,
    uint32_t uint32_t_count,
    uint64_t uint64_t_count,
    wchar_t wchar_t_count,
    long long long_long_count,
    long double long_double_count,
    unsigned char unsigned_char_count,
    unsigned short unsigned_short_count,
    unsigned int unsigned_int_count,
    unsigned long unsigned_long_count)
{
}

unsigned long* ecall_pointer_unsigned_long(
    unsigned long* p1,
    unsigned long* p2,
    unsigned long* p3,
    unsigned long* p4,
    unsigned long* p5,
    unsigned long* p6,
    unsigned long* p7,
    unsigned long* p8,
    unsigned long* p9,
    unsigned long* p10,
    unsigned long* p11,
    unsigned long* p12,
    unsigned long* p13,
    unsigned long* p14,
    unsigned long* p15,
    unsigned long* p16,
    int pcount,
    int psize)
{
    return ecall_pointer_fun_impl(
        p1,
        p2,
        p3,
        p4,
        p5,
        p6,
        p7,
        p8,
        p9,
        p10,
        p11,
        p12,
        p13,
        p14,
        p15,
        p16,
        pcount,
        psize);
}

void ecall_size_attribute_all_types(
    int* b1,
    int* b2,
    int* b3,
    int* b4,
    int* b5,
    int* b6,
    int* b7,
    int* b8,
    int* b9,
    int* b10,
    int* b11,
    int* b12,
    int* b13,
    int* b14,
    int* b15,
    int* b16,
    int* b17,
    int* b18,
    int* b19,
    int* b20,
    int* b21,
    int* b22,
    int* b23,
    char char_size,
    short short_size,
    int int_size,
    float float_size,
    double double_size,
    long long_size,
    size_t size_t_size,
    unsigned unsigned_size,
    int8_t int8_t_size,
    int16_t int16_t_size,
    int32_t int32_t_size,
    int64_t int64_t_size,
    uint8_t uint8_t_size,
    uint16_t uint16_t_size,
    uint32_t uint32_t_size,
    uint64_t uint64_t_size,
    wchar_t wchar_t_size,
    long long long_long_size,
    long double long_double_size,
    unsigned char unsigned_char_size,
    unsigned short unsigned_short_size,
    unsigned int unsigned_int_size,
    unsigned long unsigned_long_size)
{
}
