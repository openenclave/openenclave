// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

.globl abort
.type abort, @function
abort:
.cfi_startproc

    call oe_abort
    ud2

.cfi_endproc
