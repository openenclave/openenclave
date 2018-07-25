// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_TYPES_H
#define _OE_BITS_TYPES_H

#include "defs.h"

/* Basic types */
#if defined(__GNUC__)
typedef long ssize_t;
typedef unsigned long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long int64_t;
typedef unsigned long uint64_t;
typedef unsigned long uintptr_t;
typedef long ptrdiff_t;
#elif defined(_MSC_VER)
typedef long long ssize_t;
typedef unsigned long long size_t;
typedef signed char int8_t;
typedef unsigned char uint8_t;
typedef short int16_t;
typedef unsigned short uint16_t;
typedef int int32_t;
typedef unsigned int uint32_t;
typedef long long int64_t;
typedef unsigned long long uint64_t;
typedef unsigned long long uintptr_t;
typedef long long ptrdiff_t;
#else
#error "unknown compiler - please adapt basic types"
#endif

/* bool type */
#ifndef __cplusplus
#define true 1
#define false 0
#define bool _Bool
#endif

/* oe_enclave_type_t */
typedef enum _oe_enclave_type {
    OE_ENCLAVE_TYPE_UNDEFINED,
    OE_ENCLAVE_TYPE_SGX,
    __OE_ENCLAVE_TYPE_MAX = OE_ENUM_MAX,
} oe_enclave_type_t;

#endif /* _OE_BITS_TYPES_H */
