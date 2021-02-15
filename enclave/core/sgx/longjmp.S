// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

//==============================================================================
//
// void oe_longjmp(oe_jmp_buf* env, int val)
//
//     Implementation of standard longjmp() function.
//
//     %rdi := env
//     %rsi := val
//
//==============================================================================

// Modified from musl-libc root/src/setjmp/x86_64/longjmp.s

.globl oe_longjmp
.type oe_longjmp, @function
oe_longjmp:
.cfi_startproc
    mov %rsi, %rax
    // if (val == 0) then set val to 1.
    cmp $0, %rax
    jne val_is_nonzero
    mov $1, %rax # Return value (int)

val_is_nonzero:
    mov (%rdi),%rsp
    mov 8(%rdi),%rbp
    mov 24(%rdi),%rbx
    mov 32(%rdi),%r12
    mov 40(%rdi),%r13
    mov 48(%rdi),%r14
    mov 56(%rdi),%r15

    // Load indirect jump address into register and then perform the jump.
    // This pattern allows the assembler to detect and add lfence as
    // appropriate.
    mov 16(%rdi),%rdi
    jmp *%rdi
.cfi_endproc
