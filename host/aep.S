#include "asmdefs.h"

//==============================================================================
//
// void OE_AEP(void)
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
