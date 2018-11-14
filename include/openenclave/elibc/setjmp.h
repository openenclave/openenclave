// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_SETJMP_H
#define _ELIBC_SETJMP_H

#include "bits/common.h"

ELIBC_EXTERNC_BEGIN

#if defined(__linux__)
typedef struct _elibc_jmp_buf
{
    // These are the registers that are preserved across function calls
    // according to the 'System V AMD64 ABI' calling conventions:
    // RBX, RSP, RBP, R12, R13, R14, R15. In addition, elibc_setjmp() saves
    // the RIP register (instruction pointer) to know where to jump back to).
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
} elibc_jmp_buf[1];
#elif defined(_MSC_VER)
typedef struct _elibc_jmp_buf
{
    uint64_t frame;
    uint64_t rbx;
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rip;
    uint64_t spare;
    int128_t xmm6;
    int128_t xmm7;
    int128_t xmm8;
    int128_t xmm9;
    int128_t xmm10;
    int128_t xmm11;
    int128_t xmm12;
    int128_t xmm13;
    int128_t xmm14;
    int128_t xmm15;
} elibc_jmp_buf;
#endif

int elibc_setjmp(elibc_jmp_buf env);

void elibc_longjmp(elibc_jmp_buf env, int val);

#if defined(ELIBC_NEED_STDC_NAMES)

typedef elibc_jmp_buf jmp_buf;

ELIBC_INLINE
int setjmp(jmp_buf env)
{
    return elibc_setjmp(env);
}

ELIBC_INLINE
void longjmp(jmp_buf env, int val)
{
    elibc_longjmp(env, val);
}

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

ELIBC_EXTERNC_END

#endif /* _ELIBC_SETJMP_H */
