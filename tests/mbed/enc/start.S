// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//==============================================================================
//
// _start():
//
//     This enclave defines its own entry point to avoid linking liboeenclave, 
//     which results in multiple definitions of mbedtls_entropy_func(). This
//     function is defined by both libmbedcrypto and by some tests.
//
//==============================================================================

.globl _start
.type _start, @function
_start:
.cfi_startproc
    jmp oe_enter
.cfi_endproc
.size _start, .-_start

//==============================================================================
//
// oe_handle_verify_report():
//
//     Since liboeenclave is not linked, we must define a version of this 
//     function here (since liboecore depends on it). This version forces
//     an illegal instruction fault.
//
//==============================================================================

.globl oe_handle_verify_report
.type oe_handle_verify_report, @function
oe_handle_verify_report:
.cfi_startproc
    ud2
.cfi_endproc
.size oe_handle_verify_report, .-oe_handle_verify_report
