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
** oe_type_t
**
**==============================================================================
*/

typedef enum _oe_type {
    OE_NONE_T,
    OE_CHAR_T,
    OE_UCHAR_T,
    OE_WCHAR_T,
    OE_SHORT_T,
    OE_INT_T,
    OE_LONG_T,
    OE_USHORT_T,
    OE_UINT_T,
    OE_ULONG_T,
    OE_BOOL_T,
    OE_INT8_T,
    OE_UINT8_T,
    OE_INT16_T,
    OE_UINT16_T,
    OE_INT32_T,
    OE_UINT32_T,
    OE_INT64_T,
    OE_UINT64_T,
    OE_FLOAT_T,
    OE_DOUBLE_T,
    OE_SIZE_T,
    OE_SSIZE_T,
    OE_STRUCT_T,
    OE_VOID_T,
} oe_type_t;

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
** Signature of allocation and deallocation functions.
**
**==============================================================================
*/

typedef void* (*oe_alloc_proc)(size_t size);

typedef void (*oe_dealloc_proc_t)(void* ptr);

/*
**==============================================================================
**
** oe_page
**
**==============================================================================
*/

typedef OE_ALIGNED(OE_PAGE_SIZE) struct _oe_page
{
    unsigned char data[OE_PAGE_SIZE];
} oe_page;

OE_STATIC_ASSERT(__alignof(oe_page) == OE_PAGE_SIZE);

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

/*
**==============================================================================
**
** oe_ocall_context_t:
**
**==============================================================================
*/

typedef struct _oe_ocall_context
{
    uintptr_t rbp;
    uintptr_t ret;
} oe_ocall_context_t;

/*
**==============================================================================
**
** OE_LLU()
** OE_LLD()
** OE_LLX()
**
** These macros work around printf-format specifier incompatibilities across
** platforms. To illustrate the problem, consider the following snippet.
**
**     uint64_t x = 0;
**     printf("%lu\n", x);
**
** GCC compiles the above without warning, whereas MSVC warns that 'x' and
** '%lu' are incompatible. Now consider the following snippet.
**
**     uint64_t x = 0;
**     printf("%llu\n", x);
**
** GCC warns that 'x' and '%llu' are incompatible, whereas MSVC compiles
** without warning. To work around this, the OE_LLU() macro is applied as
** follows.
**
**     uint64_t x = 0;
**     printf("%llu\n", OE_LLU(x));
**
** It is important to note that the OE_LLU() macro neither casts nor promotes
** its argument, rather it converts the type of its argument from 'uint64_t'
** to 'unsigned long long', without changing the size of the integer. Note that
** the following assumption holds on all supported platforms.
**
**     sizeof(unsigned long long) == sizeof(uint64_t)
**
** Also the OE_LLU() macro fails to compile when its argument is not
** 'uint64_t' For example, the following snippet results in a compiler error.
**
**     uint32_t x = 0;
**     printf("%llu\n", OE_LLU(x)); // compiler error!
**
** To implement this macro, GCC requires a type conversion whereas MSVC does not
** (since the type of the argument already matches '%llu').
**
**==============================================================================
*/

#if defined(_MSC_VER)

#define OE_LLU(_X_) _X_
#define OE_LLD(_X_) _X_
#define OE_LLX(_X_) _X_

#elif defined(__GNUC__)

OE_INLINE unsigned long long oe_check_llu(const uint64_t* ptr)
{
    OE_STATIC_ASSERT(sizeof(unsigned long long) == sizeof(uint64_t));
    return *ptr;
}

OE_INLINE long long oe_check_lld(const int64_t* ptr)
{
    OE_STATIC_ASSERT(sizeof(long long) == sizeof(int64_t));
    return *ptr;
}

#define OE_LLU(_X_)              \
    ({                           \
        __typeof(_X_) _x_ = _X_; \
        oe_check_llu(&_x_);      \
    })

#define OE_LLD(_X_)              \
    ({                           \
        __typeof(_X_) _x_ = _X_; \
        oe_check_lld(&_x_);      \
    })

#define OE_LLX(_X_) OE_LLU(_X_)

#endif /* defined(__GNUC__) */

#endif /* _OE_BITS_TYPES_H */
