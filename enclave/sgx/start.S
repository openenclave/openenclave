// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//==============================================================================
//
// _start():
//
//     The default entry point for the enclave image.
//
//==============================================================================

.globl _start
.type _start, @function
_start:
.cfi_startproc

    /* Save the registers passed by EENTER. */
    pushq %rax
    pushq %rbx
    pushq %rcx
    pushq %rdi
    pushq %rsi

    /* Dynamically link liboecore to liboeenclave (install upcalls). */
    call oe_link_enclave

    /* Restore the registers passed by EENTER. */
    popq %rsi
    popq %rdi
    popq %rcx
    popq %rbx
    popq %rax

    jmp oe_enter
.cfi_endproc

.size _start, .-_start
