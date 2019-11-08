// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_JUMP_H
#define _OE_JUMP_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

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
} oe_jmpbuf_t;

int oe_setjmp(oe_jmpbuf_t* env);

void oe_longjmp(oe_jmpbuf_t* env, int val);

OE_EXTERNC_END

#endif /* _OE_JUMP_H */
