
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
            ohm,
            3,
            4,
            3.1415f,
            1.0 / 3.0,
            7,
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
            19) == OE_OK);

    {
        char ret = 0;
        OE_TEST(ecall_ret_char(enclave, &ret) == OE_OK);
        OE_TEST(ret == '?');
    }

    {
        wchar_t ret = 0;
        OE_TEST(ecall_ret_wchar_t(enclave, &ret) == OE_OK);
        OE_TEST(ret == ohm);
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
        long ret = 0;
        OE_TEST(ecall_ret_long(enclave, &ret) == OE_OK);
        OE_TEST(ret == 777);
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
        long double ret = 0;
        OE_TEST(ecall_ret_long_double(enclave, &ret) == OE_OK);
        OE_TEST(ret == 0.191919);
    }

    printf("=== test_basic_edl_ecalls passed\n");
}

void ocall_basic_types(
    char arg1,
    wchar_t arg2,
    short arg3,
    int arg4,
    float arg5,
    double arg6,
    long arg7,
    size_t arg8,
    unsigned arg9,
    int8_t arg10,
    int16_t arg11,
    int32_t arg12,
    int64_t arg13,
    uint8_t arg14,
    uint16_t arg15,
    uint32_t arg16,
    uint64_t arg17,
    long long arg18,
    long double arg19)
{
    ecall_basic_types_args_t args;

    // Assert types of fields of the marshaling struct.
    check_type<char>(args.arg1);
    check_type<wchar_t>(args.arg2);
    check_type<short>(args.arg3);
    check_type<int>(args.arg4);
    check_type<int>(args.arg4);
    check_type<float>(args.arg5);
    check_type<double>(args.arg6);
    check_type<long>(args.arg7);
    check_type<size_t>(args.arg8);
    check_type<unsigned int>(args.arg9);
    check_type<int8_t>(args.arg10);
    check_type<int16_t>(args.arg11);
    check_type<int32_t>(args.arg12);
    check_type<int64_t>(args.arg13);
    check_type<uint8_t>(args.arg14);
    check_type<uint16_t>(args.arg15);
    check_type<uint32_t>(args.arg16);
    check_type<uint64_t>(args.arg17);
    check_type<long long>(args.arg18);
    check_type<long double>(args.arg19);

    OE_TEST(arg1 == '?');
    OE_TEST(arg2 == ohm);
    OE_TEST(arg3 = 3);
    OE_TEST(arg4 = 4);
    OE_TEST(arg5 = 3.1415f);
    OE_TEST(arg6 = 1.0 / 3.0);
    OE_TEST(arg7 = 7);
    OE_TEST(arg8 = 8);
    OE_TEST(arg9 = 9);
    OE_TEST(arg10 = 10);
    OE_TEST(arg11 = 11);
    OE_TEST(arg12 = 12);
    OE_TEST(arg13 = 13);
    OE_TEST(arg14 = 14);
    OE_TEST(arg15 = 15);
    OE_TEST(arg16 = 16);
    OE_TEST(arg17 = 17);
    OE_TEST(arg18 = 18);
    OE_TEST(arg19 = 19);
}

char ocall_ret_char()
{
    check_return_type<ocall_ret_char_args_t, char>();
    return '?';
}

wchar_t ocall_ret_wchar_t()
{
    check_return_type<ocall_ret_wchar_t_args_t, wchar_t>();
    return ohm;
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

long double ocall_ret_long_double()
{
    check_return_type<ocall_ret_long_double_args_t, long double>();
    return 0.191919;
}
