// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../asmdefs.h"

//==============================================================================
//
// void OE_AEP(void)
//
//     Asynchronous Exception Pointer (AEP) function that handles exceptions
//     and interrupts from an enclave. A pointer to this function is passed
//     to the EENTER instruction and this function. This implementation resumes
//     execution of the enclave (ERESUME).
//
//     This function must not use or modify the stack, else it could overwrite
//     the host stack region used by enclave host stack allocaiton routines.
//
//==============================================================================

.globl OE_AEP
.type OE_AEP, @function
OE_AEP:
.cfi_startproc

// N.B, the AEP must be a ERESUME(ENCLU[3]) directly, otherwise single step
// debugging can't work. When an AEX happens, the rax in processor synthentic
// state will be set to 3, and the rbx will be set to TCS of interrupted
// enclave thread automatically. Host side doesn't need to and shouldn't do
// additional settings.

.aep:

    ENCLU
    ud2

.cfi_endproc
