
// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/host.h>
#include <openenclave/internal/tests.h>
#include "all_u.h"

void test_basic_edl_ecalls(oe_enclave_t* enclave)
{
    OE_TEST(
        ecall_basic_types(
            enclave,
            '?',
            3,
            4,
            3.1415f,
            1.0 / 3.0,
            8,
            9,
            10,
            11,
            12,
            13,
            14,
            15,
            16,
            17,
            18,
            255,
            19,
            20,
            21) == OE_OK);

    {
        char ret = 0;
        OE_TEST(ecall_ret_char(enclave, &ret) == OE_OK);
        OE_TEST(ret == '?');
    }

    {
        short ret = 0;
        OE_TEST(ecall_ret_short(enclave, &ret) == OE_OK);
        OE_TEST(ret == 444);
    }

    {
        int ret = 0;
        OE_TEST(ecall_ret_int(enclave, &ret) == OE_OK);
        OE_TEST(ret == 555);
    }

    {
        float ret = 0;
        OE_TEST(ecall_ret_float(enclave, &ret) == OE_OK);
        OE_TEST(ret == 0.333f);
    }

    {
        double ret = 0;
        OE_TEST(ecall_ret_double(enclave, &ret) == OE_OK);
        OE_TEST(ret == 0.444);
    }

    {
        size_t ret = 0;
        OE_TEST(ecall_ret_size_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == 888);
    }

    {
        unsigned ret = 0;
        OE_TEST(ecall_ret_unsigned(enclave, &ret) == OE_OK);
        OE_TEST(ret == 999);
    }

    {
        int8_t ret = 0;
        OE_TEST(ecall_ret_int8_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == 101);
    }

    {
        int16_t ret = 0;
        OE_TEST(ecall_ret_int16_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == 1111);
    }

    {
        int32_t ret = 0;
        OE_TEST(ecall_ret_int32_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == 121212);
    }

    {
        int64_t ret = 0;
        OE_TEST(ecall_ret_int64_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == 131313);
    }

    {
        uint8_t ret = 0;
        OE_TEST(ecall_ret_uint8_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == 141);
    }

    {
        uint16_t ret = 0;
        OE_TEST(ecall_ret_uint16_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == 1515);
    }

    {
        uint32_t ret = 0;
        OE_TEST(ecall_ret_uint32_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == 161616);
    }

    {
        uint64_t ret = 0;
        OE_TEST(ecall_ret_uint64_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == 171717);
    }

    {
        long long ret = 0;
        OE_TEST(ecall_ret_long_long(enclave, &ret) == OE_OK);
        OE_TEST(ret == 181818);
    }

    {
        unsigned char ret = 0;
        OE_TEST(ecall_ret_unsigned_char(enclave, &ret) == OE_OK);
        OE_TEST(ret == 255);
    }

    {
        unsigned short ret = 0;
        OE_TEST(ecall_ret_unsigned_short(enclave, &ret) == OE_OK);
        OE_TEST(ret == 191);
    }

    {
        unsigned int ret = 0;
        OE_TEST(ecall_ret_unsigned_int(enclave, &ret) == OE_OK);
        OE_TEST(ret == 202);
    }

    {
        unsigned long long ret = 0;
        OE_TEST(ecall_ret_unsigned_long_long(enclave, &ret) == OE_OK);
        OE_TEST(ret == 2222222);
    }

    {
        OE_TEST(ecall_ret_void(enclave) == OE_OK);
    }

    if (g_enabled[TYPE_WCHAR_T] && g_enabled[TYPE_LONG] &&
        g_enabled[TYPE_UNSIGNED_LONG] && g_enabled[TYPE_LONG_DOUBLE])
    {
        OE_TEST(
            ecall_basic_non_portable_types(
                enclave,
                wchar_t_value,
                long_value,
                ulong_value,
                long_double_value) == OE_OK);
    }

    if (g_enabled[TYPE_WCHAR_T])
    {
        wchar_t ret = 0;
        OE_TEST(ecall_ret_wchar_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == wchar_t_value);
    }

    if (g_enabled[TYPE_LONG])
    {
        long ret = 0;
        OE_TEST(ecall_ret_long(enclave, &ret) == OE_OK);
        OE_TEST(ret == 777);
    }

    if (g_enabled[TYPE_UNSIGNED_LONG])
    {
        unsigned long ret = 0;
        OE_TEST(ecall_ret_unsigned_long(enclave, &ret) == OE_OK);
        OE_TEST(ret == 212121);
    }

    if (g_enabled[TYPE_LONG_DOUBLE])
    {
        long double ret = 0;
        OE_TEST(ecall_ret_long_double(enclave, &ret) == OE_OK);
        OE_TEST(ret == 0.191919);
    }

    printf("=== test_basic_edl_ecalls passed\n");
}

void ocall_basic_types(
    char arg1,
    short arg2,
    int arg3,
    float arg4,
    double arg5,
    size_t arg6,
    unsigned arg7,
    int8_t arg8,
    int16_t arg9,
    int32_t arg10,
    int64_t arg11,
    uint8_t arg12,
    uint16_t arg13,
    uint32_t arg14,
    uint64_t arg15,
    long long arg16,
    unsigned char arg17,
    unsigned short arg18,
    unsigned int arg19,
    unsigned long long arg20)
{
    ocall_basic_types_args_t args;

    // Assert types of fields of the marshaling struct.
    check_type<char>(args.arg1);
    check_type<short>(args.arg2);
    check_type<int>(args.arg3);
    check_type<float>(args.arg4);
    check_type<double>(args.arg5);
    check_type<size_t>(args.arg6);
    check_type<unsigned int>(args.arg7);
    check_type<int8_t>(args.arg8);
    check_type<int16_t>(args.arg9);
    check_type<int32_t>(args.arg10);
    check_type<int64_t>(args.arg11);
    check_type<uint8_t>(args.arg12);
    check_type<uint16_t>(args.arg13);
    check_type<uint32_t>(args.arg14);
    check_type<uint64_t>(args.arg15);
    check_type<long long>(args.arg16);
    check_type<unsigned char>(args.arg17);
    check_type<unsigned short>(args.arg18);
    check_type<unsigned int>(args.arg19);
    check_type<unsigned long long>(args.arg20);

    OE_TEST(arg1 == '?');
    OE_TEST(arg2 == 3);
    OE_TEST(arg3 == 4);
    OE_TEST(arg4 == 3.1415f);
    OE_TEST(arg5 == 1.0 / 3.0);
    OE_TEST(arg6 == 8);
    OE_TEST(arg7 == 9);
    OE_TEST(arg8 == 10);
    OE_TEST(arg9 == 11);
    OE_TEST(arg10 == 12);
    OE_TEST(arg11 == 13);
    OE_TEST(arg12 == 14);
    OE_TEST(arg13 == 15);
    OE_TEST(arg14 == 16);
    OE_TEST(arg15 == 17);
    OE_TEST(arg16 == 18);
    OE_TEST(arg17 == 255);
    OE_TEST(arg18 == 19);
    OE_TEST(arg19 == 20);
    OE_TEST(arg20 == 21);
}

void ocall_basic_non_portable_types(
    wchar_t arg1,
    long arg2,
    unsigned long arg3,
    long double arg4)
{
    ocall_basic_non_portable_types_args_t args;
    // Assert types of fields of the marshaling struct.
    check_type<wchar_t>(args.arg1);
    check_type<long>(args.arg2);
    check_type<unsigned long>(args.arg3);
    check_type<long double>(args.arg4);

    OE_TEST(arg1 == wchar_t_value);
    OE_TEST(arg2 == long_value);
    OE_TEST(arg3 == ulong_value);
    OE_TEST(arg4 == long_double_value);
}

uint64_t get_host_sizeof(type_enum_t t)
{
    switch (t)
    {
        case TYPE_WCHAR_T:
            return sizeof(wchar_t);
        case TYPE_LONG:
            return sizeof(long);
        case TYPE_UNSIGNED_LONG:
            return sizeof(unsigned long);
        case TYPE_LONG_DOUBLE:
            return sizeof(long double);
        default:
            return 0;
    }
}

char ocall_ret_char()
{
    check_return_type<ocall_ret_char_args_t, char>();
    return '?';
}

wchar_t ocall_ret_wchar_t()
{
    check_return_type<ocall_ret_wchar_t_args_t, wchar_t>();
    return wchar_t_value;
}

short ocall_ret_short()
{
    check_return_type<ocall_ret_short_args_t, short>();
    return 444;
}

int ocall_ret_int()
{
    check_return_type<ocall_ret_int_args_t, int>();
    return 555;
}

float ocall_ret_float()
{
    check_return_type<ocall_ret_float_args_t, float>();
    return .333f;
}

double ocall_ret_double()
{
    check_return_type<ocall_ret_int_args_t, int>();
    return .444;
}

long ocall_ret_long()
{
    check_return_type<ocall_ret_int_args_t, int>();
    return 777;
}

size_t ocall_ret_size_t()
{
    check_return_type<ocall_ret_size_t_args_t, size_t>();
    return 888;
}

unsigned ocall_ret_unsigned()
{
    check_return_type<ocall_ret_unsigned_args_t, unsigned>();
    return 999;
}

int8_t ocall_ret_int8_t()
{
    check_return_type<ocall_ret_int8_t_args_t, int8_t>();
    return 101;
}

int16_t ocall_ret_int16_t()
{
    check_return_type<ocall_ret_int16_t_args_t, int16_t>();
    return 1111;
}

int32_t ocall_ret_int32_t()
{
    check_return_type<ocall_ret_int32_t_args_t, int32_t>();
    return 121212;
}

int64_t ocall_ret_int64_t()
{
    check_return_type<ocall_ret_int64_t_args_t, int64_t>();
    return 131313;
}

uint8_t ocall_ret_uint8_t()
{
    check_return_type<ocall_ret_uint8_t_args_t, uint8_t>();
    return 141;
}

uint16_t ocall_ret_uint16_t()
{
    check_return_type<ocall_ret_uint16_t_args_t, uint16_t>();
    return 1515;
}

uint32_t ocall_ret_uint32_t()
{
    check_return_type<ocall_ret_uint32_t_args_t, uint32_t>();
    return 161616;
}

uint64_t ocall_ret_uint64_t()
{
    check_return_type<ocall_ret_uint64_t_args_t, uint64_t>();
    return 171717;
}

long long ocall_ret_long_long()
{
    check_return_type<ocall_ret_long_long_args_t, long long>();
    return 181818;
}

unsigned char ocall_ret_unsigned_char()
{
    check_return_type<ocall_ret_unsigned_char_args_t, unsigned char>();
    return 255;
}

unsigned short ocall_ret_unsigned_short()
{
    check_return_type<ocall_ret_unsigned_short_args_t, unsigned short>();
    return 191;
}

unsigned int ocall_ret_unsigned_int()
{
    check_return_type<ocall_ret_unsigned_int_args_t, unsigned int>();
    return 202;
}

unsigned long ocall_ret_unsigned_long()
{
    check_return_type<ocall_ret_unsigned_long_args_t, unsigned long>();
    return 212121;
}

long double ocall_ret_long_double()
{
    check_return_type<ocall_ret_long_double_args_t, long double>();
    return 0.191919;
}

unsigned long long ocall_ret_unsigned_long_long()
{
    check_return_type<ocall_ret_unsigned_long_long_args_t,
                      unsigned long long>();
    return 2222222;
}

void ocall_ret_void()
{
}
