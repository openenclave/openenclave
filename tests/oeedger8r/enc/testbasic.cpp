// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../edltestutils.h"

#include <openenclave/enclave.h>
#include "basic_t.c"

void ecall_basic_types(
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
    uint64_t arg17)
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
}