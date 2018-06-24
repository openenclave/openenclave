// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//==============================================================================
//
// oe_main(): 
//
//     This function is the main entry point for the enclave when the enclave
//     is linked with the following option.
//
//         -Wl,-eoe_main
//
//==============================================================================

.globl oe_main
.type oe_main, @function
oe_main:
.cfi_startproc
    // Jump to oe_enter() in liboecore.
    jmp oe_enter
.cfi_endproc

.size oe_main, .-oe_main

//==============================================================================
//
// _start(): 
//
//     This is the default entry point for the enclave when the -Wl,-e option 
//     is not used.
//
//==============================================================================

.globl _start
.type _start, @function
_start:
.cfi_startproc
    // Jump to oe_main() above
    jmp oe_main
.cfi_endproc

.size _start, .-_start

//==============================================================================
//
// oe_call_link_enclave()
//
//     This function is placed in the same compilation unit as the entry point
//     so that it will be included in the image. It forces a linkage reference 
//     to oe_link_enclave(), which references functions so they will be 
//     included in the image. These functions will be available to subsequently
//     linked libraries.
//
//==============================================================================

.globl oe_call_link_enclave
.type oe_call_link_enclave, @function
oe_call_link_enclave:
.cfi_startproc
    call oe_link_enclave
.cfi_endproc

.size oe_call_link_enclave, .-oe_call_link_enclave
