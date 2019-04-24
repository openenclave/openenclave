// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/* These are the registers that are preserved across function calls
 * according to the 'System V AMD64 ABI' calling conventions:
 * RBX, RSP, RBP, R12, R13, R14, R15. In addition, oe_setjmp() saves
 * the RIP register (instruction pointer) to know where to jump back to).
 */
typedef struct __OE_STRUCT_JMP_BUF
{
    uint64_t rsp;
    uint64_t rbp;
    uint64_t rip;
    uint64_t rbx;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    /* Added these to align with size of MUSL jmp_buf */
    uint64_t __fl;
    uint64_t __ss[128 / sizeof(long)];
} __OE_TYPEDEF_JMP_BUF;
