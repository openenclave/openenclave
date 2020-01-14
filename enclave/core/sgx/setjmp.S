// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// void oe_setjmp(oe_jmp_buf* env)
//
//     Implementation of standard setjmp() function.
//
//     %rdi := env
//
//==============================================================================

// Modified from musl-libc root/src/setjmp/x86_64/setjmp.s

.globl oe_setjmp
.type oe_setjmp,@function
oe_setjmp:
.cfi_startproc
    lea  8(%rsp), %rdx # this is our rsp WITHOUT current ret addr
    mov  %rdx, (%rdi)
    mov  %rbp, 8(%rdi)
    mov  (%rsp), %rdx # save return addr ptr for new rip
    mov  %rdx, 16(%rdi)
    mov  %rbx, 24(%rdi)
    mov  %r12, 32(%rdi)
    mov  %r13, 40(%rdi)
    mov  %r14, 48(%rdi)
    mov  %r15, 56(%rdi)
    xorl %eax, %eax # Set return value
    ret
.cfi_endproc
