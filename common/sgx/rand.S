// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

.text
.globl  oe_rdrand
.type oe_rdrand, @function
.globl  oe_rdseed
.type oe_rdseed, @function

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

oe_rdseed:
.cfi_startproc
_rdseed_retry:
    rdseed %rax
    jc _rdseed_epilogue
    pause
    jmp _rdseed_retry
_rdseed_epilogue:
    ret
.cfi_endproc
