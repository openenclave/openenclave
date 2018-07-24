// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_TYPES_H
#define _OE_BITS_TYPES_H

#include "defs.h"

/*
**==============================================================================
**
** OE_MAX_PATH
**
**==============================================================================
*/

#if defined(MAX_PATH)
#define OE_MAX_PATH MAX_PATH
#elif defined(PATH_MAX)
#define OE_MAX_PATH PATH_MAX
#else
#define OE_MAX_PATH 1024
#endif

/*
**==============================================================================
**
** Basic types:
**
**==============================================================================
*/

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

#ifndef __cplusplus
#define true 1
#define false 0
#define bool _Bool
#endif

/* Some basic verifications */
OE_STATIC_ASSERT(sizeof(void*) == 8);
OE_STATIC_ASSERT(sizeof(ssize_t) == sizeof(void*));
OE_STATIC_ASSERT(sizeof(size_t) == sizeof(void*));
OE_STATIC_ASSERT(sizeof(int16_t) == 2);
OE_STATIC_ASSERT(sizeof(uint16_t) == 2);
OE_STATIC_ASSERT(sizeof(int32_t) == 4);
OE_STATIC_ASSERT(sizeof(uint32_t) == 4);
OE_STATIC_ASSERT(sizeof(int64_t) == 8);
OE_STATIC_ASSERT(sizeof(uint64_t) == 8);
OE_STATIC_ASSERT(sizeof(uintptr_t) == sizeof(void*));
OE_STATIC_ASSERT(sizeof(ptrdiff_t) == sizeof(void*));

/*
**==============================================================================
**
** oe_enclave_type_t
**
**==============================================================================
*/
typedef enum _oe_enclave_type {
    OE_ENCLAVE_TYPE_UNDEFINED,
    OE_ENCLAVE_TYPE_SGX,
} oe_enclave_type_t;

/*
**==============================================================================
**
** oe_va_list:
**
**==============================================================================
*/

#define oe_va_list __builtin_va_list
#define oe_va_start __builtin_va_start
#define oe_va_arg __builtin_va_arg
#define oe_va_end __builtin_va_end
#define oe_va_copy __builtin_va_copy

#endif /* _OE_BITS_TYPES_H */
