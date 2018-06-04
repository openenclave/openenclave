// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "types.h"
#include <openenclave/host.h>

PredefinedType types[] = {
    {"char", "char", "OE_CHAR_T"},
    {"int8_t", "int8_t", "OE_INT8_T"},
    {"uint8_t", "uint8_t", "OE_UINT8_T"},
    {"int16_t", "int16_t", "OE_INT16_T"},
    {"uint16_t", "uint16_t", "OE_UINT16_T"},
    {"int32_t", "int32_t", "OE_INT32_T"},
    {"uint32_t", "uint32_t", "OE_UINT32_T"},
    {"int64_t", "int64_t", "OE_INT64_T"},
    {"uint64_t", "uint64_t", "OE_UINT64_T"},
    {"float", "float", "OE_FLOAT_T"},
    {"double", "double", "OE_DOUBLE_T"},
    {"bool", "bool", "OE_BOOL_T"},
    {"size_t", "size_t", "OE_SIZE_T"},
    {"ssize_t", "ssize_t", "OE_SSIZE_T"},
    {"void", "void", "OE_VOID_T"},
    {"signed char", "signed char", "OE_CHAR_T"},
    {"unsigned char", "unsigned char", "OE_UCHAR_T"},
};

size_t ntypes = OE_COUNTOF(types);
