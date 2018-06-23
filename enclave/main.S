// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//==============================================================================
//
// oe_main(): 
//
//     This function is the main entry point for the executable. This function 
//     simply jump to oe_enter(), which is located in liboecore.
//
//==============================================================================

.globl oe_main
.type oe_main, @function
oe_main:
.cfi_startproc
    jmp oe_enter
.cfi_endproc

.size oe_main, .-oe_main

//==============================================================================
//
// oe_call_link_enclave()
//
//     This function is placed in the same compilation unit as the entry point
//     (oe_main) so that it will not be removed. It forces a linkage reference
//     to oe_link_enclave(), which references functions needed by lower level
//     libraries.
//
//==============================================================================

.globl oe_call_link_enclave
.type oe_call_link_enclave, @function
oe_call_link_enclave:
.cfi_startproc
    call oe_link_enclave
.cfi_endproc

.size oe_call_link_enclave, .-oe_call_link_enclave
