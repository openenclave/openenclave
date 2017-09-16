#include "asmdefs.h"

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

.aep:

    mov $ENCLU_ERESUME, %rax
    mov %gs:ThreadData_tcs, %rbx // TCS
    lea .aep, %rcx // AEP
    mov $0, %rdx
    ENCLU

    ud2

.cfi_endproc
