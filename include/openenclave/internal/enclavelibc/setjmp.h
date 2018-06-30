// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_ENCLAVELIBC_SETJMP_H
#define _OE_ENCLAVELIBC_SETJMP_H

#include "bits/common.h"

OE_ENCLAVELIBC_EXTERNC_BEGIN

typedef struct _oe_jmp_buf
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
} oe_jmp_buf[1];

int oe_setjmp(oe_jmp_buf env);

void oe_longjmp(oe_jmp_buf env, int val);

#if defined(OE_ENCLAVELIBC_NEED_STDC_NAMES)

typedef oe_jmp_buf jmp_buf;

OE_ENCLAVELIBC_INLINE
int setjmp(jmp_buf env)
{
    return oe_setjmp(env);
}

OE_ENCLAVELIBC_INLINE
void longjmp(jmp_buf env, int val)
{
    return oe_longjmp(env, val);
}

#endif /* defined(OE_ENCLAVELIBC_NEED_STDC_NAMES) */

OE_ENCLAVELIBC_EXTERNC_END

#endif /* _OE_ENCLAVELIBC_SETJMP_H */
