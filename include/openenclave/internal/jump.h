// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_JUMP_H
#define _OE_JUMP_H

#include <openenclave/bits/types.h>
#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

typedef struct _oe_jmpbuf
{
    /* These are the registers that are preserved across function calls
     * according to the 'System V AMD64 ABI' calling conventions:
     * RBX, RSP, RBP, R12, R13, R14, R15. In addition, oe_setjmp() saves
     * the RIP register (instruction pointer) to know where to jump back to).
     */
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
#if defined(_WIN32)
    /* Addition registers preserved per Windows ABI */
    uint64_t rdi;
    uint64_t rsi;
    uint64_t frame; /* Caller's frame pointer */
    uint32_t MxCsr; /* Floating pointer control */
    uint32_t spare;
    uint128_t xmm6;
    uint128_t xmm7;
    uint128_t xmm8;
    uint128_t xmm9;
    uint128_t xmm10;
    uint128_t xmm11;
    uint128_t xmm12;
    uint128_t xmm13;
    uint128_t xmm14;
    uint128_t xmm15;
#endif /* defined(_WIN32) */
} oe_jmpbuf_t;

OE_STATIC_ASSERT((sizeof(oe_jmpbuf_t) & 0xf) == 0);

int oe_setjmp(oe_jmpbuf_t* env);

void oe_longjmp(oe_jmpbuf_t* env, int val);

OE_EXTERNC_END

#endif /* _OE_JUMP_H */
