// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _TD_H
#define _TD_H

#include <openenclave/internal/jump.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/types.h>
#include "asmdefs.h"

/*
**==============================================================================
**
** Callsite
**
**     This structure stores callsite information saved when initiating an
**     OCALL (__oe_ocall). It stores:
**
**         (*) Registers values at the callsite
**         (*) Instruction address at the callsite
**         (*) Pointer to the next callsite on the list
**
**     When the OCALL returns, a callsite is used restore the registers
**     and to jump (oe_longjmp) to the instruction where the callsite
**     information was recorded (by oe_setjmp).
**
**     Since ECALLS and OCALLS can be nested, more than one instance of this
**     structure is needed, so callsites are kept on the enclave stack and
**     linked together.
**
**     General flow:
**
**         (1) ECALL pushes a zero-filled callsite on the stack
**         (2) OCALL saves the callsite information (oe_setjmp)
**         (3) ORET jumps to the callsite (oe_longjmp)
**         (4) Control returned to caller (__oe_ocall)
**         (5) ERET pops the callsite from the stack
**
**==============================================================================
*/

typedef struct _callsite Callsite;

struct _callsite
{
    /* Enclave callsite stored here when exiting to make an OCALL */
    oe_jmpbuf_t jmpbuf;

    /* Pointer to the ocall context */
    oe_ocall_context_t* ocall_context;

    /* Pointer to next ECALL context */
    Callsite* next;
};

/*
**==============================================================================
**
** td_t methods:
**
**==============================================================================
*/

void td_push_callsite(td_t* td, Callsite* ec);

void td_pop_callsite(td_t* td);

td_t* td_from_tcs(void* tcs);

void* td_to_tcs(const td_t* td);

void td_init(td_t* td);

void td_clear(td_t* td);

bool td_initialized(td_t* td);

#endif /* _TD_H */
