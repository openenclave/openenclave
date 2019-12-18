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
    # Some versions of clang generate code that relies on the return address
    # of this stack frame to be the address that was actually jumped to. Set
    # the stored %rip value as the return address for the stack frame directly
    # above the one we're returning to.
    mov 16(%rdi),%rcx # Get stored %rip
    mov (%rdi),%rdx # Get stored %rsp
    mov %rcx,-0x8(%rdx)

    mov (%rdi),%rsp
    mov 8(%rdi),%rbp
    mov 24(%rdi),%rbx
    mov 32(%rdi),%r12
    mov 40(%rdi),%r13
    mov 48(%rdi),%r14
    mov 56(%rdi),%r15
    jmp *16(%rdi)
.cfi_endproc
