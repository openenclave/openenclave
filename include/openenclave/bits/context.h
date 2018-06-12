// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_CONTEXT_H
#define _OE_BITS_CONTEXT_H

#ifndef __ASSEMBLER__
#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include "constants_x64.h"

// X87 and SSE data.
typedef struct _oe_basic_x_state
{
    uint8_t blob[512];
} OE_ALIGNED(16) OE_BASIC_XSTATE;

typedef struct _oe_context
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
} oe_context_t;

OE_CHECK_SIZE(sizeof(oe_context_t), OE_CONTEXT_SIZE);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, flags), OE_CONTEXT_FLAGS);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, rax), OE_CONTEXT_RAX);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, rbx), OE_CONTEXT_RBX);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, rcx), OE_CONTEXT_RCX);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, rdx), OE_CONTEXT_RDX);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, rbp), OE_CONTEXT_RBP);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, rsp), OE_CONTEXT_RSP);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, rdi), OE_CONTEXT_RDI);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, rsi), OE_CONTEXT_RSI);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, r8), OE_CONTEXT_R8);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, r9), OE_CONTEXT_R9);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, r10), OE_CONTEXT_R10);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, r11), OE_CONTEXT_R11);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, r12), OE_CONTEXT_R12);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, r13), OE_CONTEXT_R13);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, r14), OE_CONTEXT_R14);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, r15), OE_CONTEXT_R15);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, rip), OE_CONTEXT_RIP);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, mxcsr), OE_CONTEXT_MXCSR);
OE_CHECK_SIZE(OE_OFFSETOF(oe_context_t, basic_xstate), OE_CONTEXT_FLOAT);

void oe_snap_current_context(oe_context_t* oe_context);
void oe_restore_partial_context(oe_context_t* oe_context);
void oe_continue_execution(oe_context_t* oe_context);

typedef struct _oe_exception_record
{
    // Exception code.
    uint32_t code;

    // Exception flags.
    uint32_t flags;

    // Exception address.
    uint64_t address;

    // Context.
    oe_context_t* context;
} oe_exception_record_t;

typedef uint64_t (*oe_vectored_exception_handler)(
    oe_exception_record_t* exceptionContext);
#endif // !__ASSEMBLER__

#endif /* _OE_BITS_CONTEXT_H */
