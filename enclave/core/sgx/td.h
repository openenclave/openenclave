// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _TD_H
#define _TD_H

#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/sgx/td.h>
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

/* Some basic td function do not have the opportunity to keep consistency of
   td then may trigger stack check fail. Such functions are moved to a separate
   source file td_basic.c and the stack guard protector is disabled by force
   through fno-stack-protector option.
*/

/*
**==============================================================================
**
** oe_sgx_td_t methods defined in td.c
**
**==============================================================================
*/

void td_push_callsite(oe_sgx_td_t* td, Callsite* ec);

oe_sgx_td_t* td_from_tcs(void* tcs);

void* td_to_tcs(const oe_sgx_td_t* td);

bool td_initialized(oe_sgx_td_t* td);

/*
**==============================================================================
**
** oe_sgx_td_t methods defined in td_basic.c
**
**==============================================================================
*/

void td_pop_callsite(oe_sgx_td_t* td);

void td_init(oe_sgx_td_t* td);

void td_clear(oe_sgx_td_t* td);

#endif /* _TD_H */
