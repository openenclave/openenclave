// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

//==============================================================================
//
// _start():
//
//     The default entry point for the enclave image. This entry point jumps
//     directly to the oe_enter() function in liboecore.
//
//==============================================================================

.globl _start
.type _start, @function
_start:
.cfi_startproc
    jmp oe_enter
.cfi_endproc

.size _start, .-_start
