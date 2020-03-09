// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

.text
.globl  oe_rdrand
.type oe_rdrand, @function

oe_rdrand:
.cfi_startproc
_rdrand_retry:
    rdrand %rax
    jc _rdrand_epilogue
    pause
    jmp _rdrand_retry
_rdrand_epilogue:
    ret
.cfi_endproc
