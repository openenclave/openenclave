// Copyright (c) Open Enclave SDK contributors.
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


//==============================================================================
//
// uint64_t OE_AEP_ADDRESS
//
//     The address of the ENCLU instruction is stored in this variable.
//     If the OE_AEP function were to be used in code, the linker could create
//     thunks that wrap the function. For example, when incremental linking is
//     enabled, the linker on windows creates an entry in the ILT table for
//     each function and uses that wherever the function is referenced.
//     Thus OE_AEP would end up pointing to the thunk in the ILT which is not
//     what we want. The OE_AEP_ADDRESS variable gives the precise location of
//     the ENCLU instruction.
//
//==============================================================================
.globl OE_AEP_ADDRESS
.section .rodata
.align 8
OE_AEP_ADDRESS:	.quad .aep
