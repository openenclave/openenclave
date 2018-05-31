// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file types.h
 *
 * This file defines Open Enclave types.
 *
 */
#ifndef _OE_TYPES_H
#define _OE_TYPES_H

#include "defs.h"

/*
 * EAFI_MAX_PATH
 */

#if defined(MAX_PATH)
#define OE_MAX_PATH MAX_PATH
#elif defined(PATH_MAX)
#define OE_MAX_PATH PATH_MAX
#else
#define OE_MAX_PATH 1024
#endif

// Basic types and Printf format specifiers

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

#define OE_I64D_F "%ld"
#define OE_I64U_F "%lu"
#define OE_I64X_F "%lx"

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

#define OE_I64D_F "%I64d"
#define OE_I64U_F "%I64u"
#define OE_I64X_F "%I64x"

#else
#error "unknown compiler - please adapt basic types"
#endif

/* Some basic verifications */
OE_STATIC_ASSERT(sizeof(void*) == 8);
OE_STATIC_ASSERT(sizeof(ssize_t) == sizeof(void*));
OE_STATIC_ASSERT(sizeof(size_t) == sizeof(void*));
OE_STATIC_ASSERT(sizeof(int16_t) == 2);
OE_STATIC_ASSERT(sizeof(uint16_t) == 2);
OE_STATIC_ASSERT(sizeof(int32_t) == 4);
OE_STATIC_ASSERT(sizeof(int32_t) == 4);
OE_STATIC_ASSERT(sizeof(int64_t) == 8);
OE_STATIC_ASSERT(sizeof(uint64_t) == 8);
OE_STATIC_ASSERT(sizeof(uintptr_t) == sizeof(void*));
OE_STATIC_ASSERT(sizeof(ptrdiff_t) == sizeof(void*));

#ifndef __cplusplus
#define true 1
#define false 0
#define bool _Bool
#endif

/**
 * Integer limits:
 */
#define OE_MIN_SINT8 (-128)
#define OE_MAX_SINT8 127
#define OE_MAX_UINT8 255

#define OE_MIN_SINT16 (-32768)
#define OE_MAX_SINT16 32767
#define OE_MAX_UINT16 65535

#define OE_MIN_SINT32 (-2147483647 - 1)
#define OE_MAX_SINT32 2147483647
#define OE_MAX_UINT32 4294967295U

#define OE_MIN_SINT64 (-9223372036854775807L - 1L)
#define OE_MAX_SINT64 9223372036854775807L
#define OE_MAX_UINT64 18446744073709551615UL

#define OE_MIN_CHAR OE_MIN_SINT8
#define OE_MAX_CHAR OE_MAX_SINT8
#define OE_MAX_UCHAR OE_MAX_UINT8

#define OE_MIN_SHORT OE_MIN_SINT16
#define OE_MAX_SHORT OE_MAX_SINT16
#define OE_MAX_USHORT OE_MAX_SINT16

#define OE_MIN_INT OE_MIN_SINT32
#define OE_MAX_INT OE_MAX_SINT32
#define OE_MAX_UINT OE_MAX_UINT32

#define OE_MIN_LLONG OE_MIN_SINT64
#define OE_MAX_LLONG OE_MAX_SINT64
#define OE_MAX_ULLONG OE_MAX_UINT64

#define OE_MAX_SIZE_T OE_MAX_UINT64

/*
**===========================================================================
**OE_Type:
**===========================================================================
*/
typedef enum _OE_Type {
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
} OE_Type;

/**
 * OE_EnclaveType: Defines the enclave type. Currently always
 * OE_ENCLAVE_TYPE_SGX
 */
typedef enum _OE_EnclaveType {
    OE_ENCLAVE_TYPE_UNDEFINED,
    OE_ENCLAVE_TYPE_SGX,
} OE_EnclaveType;

/*
 * Signature of allocation and deallocation functions.
 */
typedef void* (*OE_AllocProc)(size_t size);

typedef void (*OE_DeallocProc)(void* ptr);

/*
**===========================================================================
**OE_Page: Aligned Page of size 4K
**===========================================================================
*/
typedef OE_ALIGNED(OE_PAGE_SIZE) struct _OE_Page
{
    unsigned char data[OE_PAGE_SIZE];
} OE_Page;

OE_STATIC_ASSERT(__alignof(OE_Page) == OE_PAGE_SIZE);

/**
 * OE_va_list: Points to __builtin_va_list macros
 */
#define OE_va_list __builtin_va_list
#define OE_va_start __builtin_va_start
#define OE_va_arg __builtin_va_arg
#define OE_va_end __builtin_va_end
#define OE_va_copy __builtin_va_copy

/*! @brief Structure that holds the call context
 *
 * Pointers to RBP and RET address are saved as part of the call context
 */
typedef struct _OE_OCallContext
{
    uintptr_t rbp;
    uintptr_t ret;
} OE_OCallContext;

/**
 * Contains X87 and SSE data
 */
typedef struct _OE_BASIC_XSTATE
{
    uint8_t blob[512]; /**< Holds XState i.e. X87 and SSE data */
} OE_ALIGNED(16) OE_BASIC_XSTATE;

/**
 * \typedef OE_CONTEXT: typedef to structure _OE_CONTEXT
 * \struct _OE_CONTEXT: Necessary x64 registers/state that can be
 * saved before an exception and restored after the exception has been handled
 * in the enclave.
 */
typedef struct _OE_CONTEXT
{
    uint64_t flags; /**< Flags */

    /**< Integer registers. */
    uint64_t rax;
    uint64_t rbx;
    uint64_t rcx;
    uint64_t rdx;

    uint64_t rbp;
    uint64_t rsp;

    uint64_t rdi;
    uint64_t rsi;

    uint64_t r8;
    uint64_t r9;
    uint64_t r10;
    uint64_t r11;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;

    uint64_t rip;

    // Don't need to manipulate the segment registers directly.
    // Ignore them: CS, DS, ES, SS, GS, and FS.

    uint32_t mxcsr; /**< SSE control flags */

    OE_BASIC_XSTATE basic_xstate; /**< @OE_BASIC_XSTATE - Basic XState */

    // Don't need to manipulate other XSTATE (AVX etc.).
} OE_CONTEXT;

/**
 * Exception context structure with the exception code, flags, address and
 * calling context of the exception.
 */
typedef struct _OE_EXCEPTION_RECORD
{
    uint32_t code;       /**< Exception code */
    uint32_t flags;      /**< Exception flags */
    uint64_t address;    /**< Exception address */
    OE_CONTEXT* context; /**< Structure that holds the calling context i.e.
                            pointers to RBP and RET address */
} OE_EXCEPTION_RECORD;

/**
 * POE_VECTORED_EXCEPTION_HANDLER: Pointer to Vectored exception handler
 * registered in the enclave.
 * @param exceptionContext - Holds the exception code, flags, address and
 * calling context.
 */
typedef uint64_t (*POE_VECTORED_EXCEPTION_HANDLER)(
    OE_EXCEPTION_RECORD* exceptionContext);

#endif /* _OE_TYPES_H */
