// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file exception.h
 *
 * This file defines data structures to setup vectored exception handlers in the
 * enclave.
 *
 */
#ifndef _OE_EXCEPTION_H
#define _OE_EXCEPTION_H

#ifndef __ASSEMBLER__
#include "defs.h"
#include "types.h"

/**
 * Exception codes used by the vectored exception handlers
 */

#define OE_EXCEPTION_DIVIDE_BY_ZERO 0x0
#define OE_EXCEPTION_BREAKPOINT 0x1
#define OE_EXCEPTION_BOUND_OUT_OF_RANGE 0x2
#define OE_EXCEPTION_ILLEGAL_INSTRUCTION 0x3
#define OE_EXCEPTION_ACCESS_VIOLATION 0x4
#define OE_EXCEPTION_PAGE_FAULT 0x5
#define OE_EXCEPTION_X87_FLOAT_POINT 0x6
#define OE_EXCEPTION_MISALIGNMENT 0x7
#define OE_EXCEPTION_SIMD_FLOAT_POINT 0x8
#define OE_EXCEPTION_UNKOWN 0xFFFFFFFF

/**
 * Exception flags used by the vectored exception handlers
 */

#define OE_EXCEPTION_HARDWARE 0x1
#define OE_EXCEPTION_SOFTWARE 0x2

/**
 * @typedef OE_BASIC_XSTATE: typedef to structure _OE_BASIC_XSTATE
 * @struct _OE_BASIC_XSTATE: Blob that contains X87 and SSE data
 */
typedef struct _OE_BASIC_XSTATE
{
    uint8_t blob[512]; /**< Holds XState i.e. X87 and SSE data */
} OE_ALIGNED(16) OE_BASIC_XSTATE;

/**
 * @typedef OE_CONTEXT: typedef to structure _OE_CONTEXT
 * @struct _OE_CONTEXT: Register state to  be saved before an exception and
 * restored after the exception has been handled in the enclave.
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

    OE_BASIC_XSTATE basic_xstate; /**< Basic XState */

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

#endif // !__ASSEMBLER__

#endif /* _OE_EXCEPTION_H */
