// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

.globl _start
.type _start, @function
_start:
.cfi_startproc
    jmp oe_enter
.cfi_endproc

.size _start, .-_start
