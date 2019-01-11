// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

.text
.globl  _rdrand

_rdrand:
    pushq   %rbp
    movq    %rsp, %rbp

_rdrand_retry:
    rdrand %rax
    jnc _rdrand_retry

    leave
    ret

