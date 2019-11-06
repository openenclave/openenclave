// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// void oe_setjmp(oe_jmp_buf env)
//
//     Implementation of standard setjmp() function.
//
//     %rdi := env
//
//==============================================================================

/* ATTN: WINPORT */

.globl oe_setjmp
.type oe_setjmp,@function
oe_setjmp:
.cfi_startproc
    mov %rbx, (%rdi)
    mov %rbp, 8(%rdi)
    mov %r12, 16(%rdi)
    mov %r13, 24(%rdi)
    mov %r14, 32(%rdi)
    mov %r15, 40(%rdi)
    lea 8(%rsp), %rdx
    mov %rdx, 48(%rdi)
    mov (%rsp), %rdx
    mov %rdx, 56(%rdi)
    xor %rax, %rax
    ret
.cfi_endproc
