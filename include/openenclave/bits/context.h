// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_CONTEXT_H
#define _OE_BITS_CONTEXT_H

#ifndef __ASSEMBLER__
#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include "constants_x64.h"

// X87 and SSE data.
typedef struct _OE_BasicXState
{
    uint8_t blob[512];
} OE_ALIGNED(16) OE_BASIC_XSTATE;

typedef struct _OE_Context
{
    // Flags.
    uint64_t flags;

    // Integer registers.
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

    // SSE control flags.
    uint32_t mxcsr;

    // Basic XState.
    OE_BASIC_XSTATE basic_xstate;

    // Don't need to manipulate other XSTATE (AVX etc.).
} OE_Context;

OE_CHECK_SIZE(sizeof(OE_Context), OE_CONTEXT_SIZE);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, flags), OE_CONTEXT_FLAGS);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, rax), OE_CONTEXT_RAX);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, rbx), OE_CONTEXT_RBX);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, rcx), OE_CONTEXT_RCX);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, rdx), OE_CONTEXT_RDX);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, rbp), OE_CONTEXT_RBP);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, rsp), OE_CONTEXT_RSP);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, rdi), OE_CONTEXT_RDI);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, rsi), OE_CONTEXT_RSI);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, r8), OE_CONTEXT_R8);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, r9), OE_CONTEXT_R9);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, r10), OE_CONTEXT_R10);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, r11), OE_CONTEXT_R11);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, r12), OE_CONTEXT_R12);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, r13), OE_CONTEXT_R13);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, r14), OE_CONTEXT_R14);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, r15), OE_CONTEXT_R15);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, rip), OE_CONTEXT_RIP);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, mxcsr), OE_CONTEXT_MXCSR);
OE_CHECK_SIZE(OE_OFFSETOF(OE_Context, basic_xstate), OE_CONTEXT_FLOAT);

void OE_SnapCurrentContext(OE_Context* oe_context);
void OE_RestorePartialContext(OE_Context* oe_context);
void OE_ContinueExecution(OE_Context* oe_context);

typedef struct _OE_ExceptionRecord
{
    // Exception code.
    uint32_t code;

    // Exception flags.
    uint32_t flags;

    // Exception address.
    uint64_t address;

    // Context.
    OE_Context* context;
} OE_ExceptionRecord;

typedef uint64_t (*OE_VectoredExceptionHandler)(
    OE_ExceptionRecord* exceptionContext);
#endif // !__ASSEMBLER__

#endif /* _OE_BITS_CONTEXT_H */
