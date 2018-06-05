// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _TD_H
#define _TD_H

#include <openenclave/internal/jump.h>
#include <openenclave/internal/sgxtypes.h>
#include "asmdefs.h"

/*
**==============================================================================
**
** Callsite
**
**     This structure stores callsite information saved when initiating an
**     OCALL (__OE_Ocall). It stores:
**
**         (*) Registers values at the callsite
**         (*) Instruction address at the callsite
**         (*) Pointer to the next callsite on the list
**
**     When the OCALL returns, a callsite is used restore the registers
**     and to jump (OE_Longjmp) to the instruction where the callsite
**     information was recorded (by OE_Setjmp).
**
**     Since ECALLS and OCALLS can be nested, more than one instance of this
**     structure is needed, so callsites are kept on the enclave stack and
**     linked together.
**
**     General flow:
**
**         (1) ECALL pushes a zero-filled callsite on the stack
**         (2) OCALL saves the callsite information (OE_Setjmp)
**         (3) ORET jumps to the callsite (OE_Longjmp)
**         (4) Control returned to caller (__OE_Ocall)
**         (5) ERET pops the callsite from the stack
**
**==============================================================================
*/

typedef struct _Callsite Callsite;

struct _Callsite
{
    /* Enclave callsite stored here when exiting to make an OCALL */
    OE_Jmpbuf jmpbuf;

    /* Pointer ot the ocall context */
    OE_OCallContext* ocallContext;

    /* Pointer to next ECALL context */
    Callsite* next;
};

/*
**==============================================================================
**
** TD methods:
**
**==============================================================================
*/

void TD_PushCallsite(TD* td, Callsite* ec);

void TD_PopCallsite(TD* td);

TD* TD_FromTCS(void* tcs);

void* TD_ToTCS(const TD* td);

TD* TD_Get(void);

void TD_Init(TD* td);

void TD_Clear(TD* td);

bool TD_Initialized(TD* td);

#endif /* _TD_H */
