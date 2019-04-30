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
