// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//==============================================================================
//
// _start(): 
//
//     The default entry point for the enclave image. This is not used at all
//     by OP-TEE; it only serves to enable proper symbol resolution at
//     link-time. This function is set as the entry point in add_enclave.cmake
//     by passing "--entry _start" to the linker.
//
//==============================================================================

.globl _start
.type _start, @function
_start:
.cfi_startproc
    b __ta_entry
.cfi_endproc

.size _start, .-_start

//==============================================================================
//
// oe_call_link_enclave()
//
//     This function is placed in the same compilation unit as the entry point
//     so that it will be included in the image. It forces a linkage reference 
//     to oe_link_enclave(), which forces various symbols to be included in the
//     enclave image. All these symbols will be available to subsequently
//     linked libraries.
//
//==============================================================================

.globl oe_call_link_enclave
.type oe_call_link_enclave, @function
oe_call_link_enclave:
.cfi_startproc
    bl oe_link_enclave
.cfi_endproc

.size oe_call_link_enclave, .-oe_call_link_enclave
