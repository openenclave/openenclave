// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

.globl abort
.type abort, @function
abort:
.cfi_startproc

    call oe_abort
    ud2

.cfi_endproc
