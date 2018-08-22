// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/enclave.h>
#include <openenclave/internal/tests.h>
#include <stdio.h>
#include <algorithm>
#include "pointer_t.c"

template <typename T, typename F>
static void test_ocall_pointer_fun(F ocall_pointer_fun)
{
    // 1 element arrays.
    T p1[1] = {1}, p2[1] = {1}, p3[1] = {1};

    // 16 element arrays.
    T p4[16], p5[16], p6[16];
    for (size_t i = 0; i < 16; ++i)
        p4[i] = p5[i] = p6[i] = i + 1;

    static_assert((80 / sizeof(T)) * sizeof(T) == 80, "invalid size");
    // arrays with size = 80 bytes.
    size_t count = 80 / sizeof(T);
    T p7[count], p8[count], p9[count];

    for (size_t i = 0; i < count; ++i)
        p7[i] = p8[i] = p9[i] = i + 1;

    T p10[16];
    for (size_t i = 0; i < 16; ++i)
        p10[i] = i + 1;

    T* ret = NULL;
    OE_TEST(
        ocall_pointer_fun(&ret, p1, p2, p3, p4, p5, p6, p7, p8, p9, p10) ==
        OE_OK);
    {
        // p2, p3 are modified.
        OE_TEST(p2[0] == 2);
        OE_TEST(p3[0] == 2);

        // p5 is reversed.
        T exp[] = {16, 15, 14, 13, 12, 11, 10, 9, 8, 7, 6, 5, 4, 3, 2, 1};
        OE_TEST(memcmp(exp, p5, sizeof(exp)) == 0);

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

    // Call with nulls.
    OE_TEST(
        ocall_pointer_fun(
            &ret, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL, NULL) ==
        OE_OK);
}

OE_ECALL void test_pointer_edl_ocalls(void*)
{
    test_ocall_pointer_fun<char>(ocall_pointer_char);
    test_ocall_pointer_fun<short>(ocall_pointer_short);
    test_ocall_pointer_fun<int>(ocall_pointer_int);
    test_ocall_pointer_fun<float>(ocall_pointer_float);
    test_ocall_pointer_fun<double>(ocall_pointer_double);
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

    OE_TEST(oe_call_host("ocall_pointer_assert_all_called", NULL) == OE_OK);
    printf("=== test_pointer_edl_ocalls passed\n");
}

template <typename T>
static void reverse(T* arr, size_t len)
{
    for (size_t i = 0; i < len / 2; ++i)
        std::swap(arr[i], arr[len - 1 - i]);
}

static int num_ecalls = 0;

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
        size_t count = 80 / sizeof(T);
        T exp[count];
        for (size_t i = 0; i < count; ++i)
            exp[i] = i + 1;

        //
        if (p7)
        {
            OE_TEST(oe_is_within_enclave(p7, 80));
            OE_TEST(memcmp(p7, exp, 80) == 0);

            // change p7. Should not have any effect on host.
            memset(p7, 0, 80);
        }

        // in-out
        if (p8)
        {
            OE_TEST(oe_is_within_enclave(p8, 80));
            OE_TEST(memcmp(p8, exp, 80) == 0);
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

OE_ECALL void ecall_pointer_assert_all_called(void*)
{
    // Each of the 16 functions above is called twice.
    // Once with arrays and then with nulls.
    OE_TEST(num_ecalls == 32);
}
