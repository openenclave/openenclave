// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_CONTEXT_H
#define _OE_INTERNAL_CONTEXT_H

#ifndef __ASSEMBLER__
#include <openenclave/bits/defs.h>
#include <openenclave/bits/exception.h>
#include <openenclave/bits/types.h>
#include "constants_x64.h"

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

typedef struct oe_enclu_context
{
    uint8_t fxstate[512];
    uint64_t mxcsr;

    void* tcs;
    uint64_t aep;
    uint64_t arg1;
    uint64_t arg2;
} oe_enclu_context_t;

#endif // !__ASSEMBLER__

#endif /* _OE_INTERNAL_CONTEXT_H */
