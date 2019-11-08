// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// void oe_longjmp(oe_jmp_buf env, int val)
//
//     Implementation of standard longjmp() function.
//
//     %rdi := env
//     %rsi := val
//
//==============================================================================

/* ATTN: WINPORT */

.globl oe_longjmp
.type oe_longjmp, @function
oe_longjmp:
.cfi_startproc
    mov %rsi, %rax
    // if (val == 0) then set val to 1.
    cmp $0, %rax
    jne val_is_nonzero
    mov $1, %rax
val_is_nonzero:
    mov (%rdi), %rbx
    mov 8(%rdi), %rbp
    mov 16(%rdi), %r12
    mov 24(%rdi), %r13
    mov 32(%rdi), %r14
    mov 40(%rdi), %r15
    mov 48(%rdi), %rdx
    mov %rdx, %rsp
    mov 56(%rdi), %rdx
    jmp *%rdx
.cfi_endproc
