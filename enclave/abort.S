// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

.globl OE_Abort
.hidden OE_Abort
.type OE_Abort, @function
OE_Abort:
.cfi_startproc

    ud2

.cfi_endproc
