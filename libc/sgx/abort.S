// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

.globl abort
.type abort, @function
abort:
.cfi_startproc
    sub $8, %rsp // align rsp so that the call below is ABI compliant
    call oe_abort
    ud2

.cfi_endproc
