// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "td.h"
#include <openenclave/bits/sgx/sgxtypes.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/rdrand.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>
#include "asmdefs.h"
#include "thread.h"
#include "threadlocal.h"

#define TD_FROM_TCS (5 * OE_PAGE_SIZE)

OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, magic) == td_magic);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, depth) == td_depth);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, host_rcx) == td_host_rcx);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, host_rsp) == td_host_rsp);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, host_rbp) == td_host_rbp);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_sgx_td_t, host_previous_rsp) == td_host_previous_rsp);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_sgx_td_t, host_previous_rbp) == td_host_previous_rbp);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, oret_func) == td_oret_func);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, oret_arg) == td_oret_arg);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, callsites) == td_callsites);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, simulate) == td_simulate);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_sgx_td_t, host_ecall_context) == td_host_ecall_context);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_sgx_td_t, host_previous_ecall_context) ==
    td_host_previous_ecall_context);

// Static asserts for consistency with
// debugger/pythonExtension/gdb_sgx_plugin.py
OE_STATIC_ASSERT(td_callsites == 0xf0);
OE_STATIC_ASSERT(OE_OFFSETOF(Callsite, ocall_context) == 0x40);
OE_STATIC_ASSERT(TD_FROM_TCS == 0x5000);
OE_STATIC_ASSERT(sizeof(oe_ocall_context_t) == (2 * sizeof(uintptr_t)));

/*
**==============================================================================
**
** oe_get_thread_data()
**
**     Gets a pointer to the thread data structure from the GS segment.
**     The oe_sgx_td_t data structure is a concatenation of the oe_thread_data_t
*with
**     extended fields, and this method returns the td->base offset with as the
**     appropriate type.
**
**==============================================================================
*/

oe_thread_data_t* oe_get_thread_data()
{
    oe_sgx_td_t* td = oe_sgx_get_td();
    return &(td->base);
}

/*
**==============================================================================
**
** td_push_callsite()
**
**     Insert the Callsite structure for the current ECALL at the
**     front of the oe_sgx_td_t.callsites list.
**
**==============================================================================
*/

void td_push_callsite(oe_sgx_td_t* td, Callsite* callsite)
{
    callsite->next = td->callsites;
    td->callsites = callsite;
    td->depth++;
}

/*
**==============================================================================
**
**     !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
**     According to the implementation of Windows debugger and the previous
**     design of this structure, the debugger need the GS segment register
**     to find oe_sgx_td_t. Since oe_sgx_td_t is moved to current FS page, now
*GS segment
**     register needs to point to this page. Do not change the GS segment
**     resigter until it is solved on Windows debugger.
**     !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
**
** td_from_tcs()
**
**     This function calculates the address of the oe_sgx_td_t (thread data
*structure)
**     relative to the TCS (Thread Control Structure) page. The oe_sgx_td_t
*resides in
**     a page pointed to by the FS (segment register). This page occurs 5 pages
**     after the TCS page. The layout is as follows:
**
**         +----------------------------+
**         | TCS Page                   |
**         +----------------------------+
**         | SSA (State Save Area) 0    |
**         +----------------------------+
**         | SSA (State Save Area) 1    |
**         +----------------------------+
**         | Guard Page                 |
**         +----------------------------+
**         | Thread local storage       |
**         +----------------------------+
**         | FS/GS Page (oe_sgx_td_t + tsp)    |
**         +----------------------------+
**
**     This layout is determined by the enclave builder. See:
**
**         ../host/sgx/create.c (_add_control_pages)
**
**     The FS segment register is set by the EENTER instruction and the td_t
**     page is zero filled upon initial enclave entry. Software sets the
**     contents of the oe_sgx_td_t when it first determines that
*oe_sgx_td_t.self_addr is
**     zero.
**
**==============================================================================
*/

oe_sgx_td_t* td_from_tcs(void* tcs)
{
    return (oe_sgx_td_t*)((uint8_t*)tcs + TD_FROM_TCS);
}

/*
**==============================================================================
**
** td_to_tcs()
**
**     Compute a TCS pointer from a oe_sgx_td_t.
**
**==============================================================================
*/

void* td_to_tcs(const oe_sgx_td_t* td)
{
    return (uint8_t*)td - TD_FROM_TCS;
}

/*
**==============================================================================
**
** oe_sgx_get_td()
**
**     Returns a pointer to the thread data structure for the current thread.
**     This structure resides in the GS segment. Offset zero of this segment
**     contains the oe_thread_data_t.self_addr field (a back pointer to the
**     structure itself). This field is zero until the structure is initialized
**     by __oe_handle_main (which happens immediately an EENTER).
**
**==============================================================================
*/

oe_sgx_td_t* oe_sgx_get_td()
{
    oe_sgx_td_t* td;

    asm("mov %%fs:0, %0" : "=r"(td));

    return td;
}

/*
**==============================================================================
**
** td_initialized()
**
**     Returns TRUE if this thread data structure (oe_sgx_td_t) is initialized.
*An
**     initialized oe_sgx_td_t meets the following conditions:
**
**         (1) td is not null
**         (2) td->base.self_addr == td
**         (3) td->magic == TD_MAGIC
**
**==============================================================================
*/

bool td_initialized(oe_sgx_td_t* td)
{
    if (td && td->magic == TD_MAGIC && td->base.self_addr == (uint64_t)td)
        return true;

    return false;
}
