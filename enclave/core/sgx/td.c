// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "td.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/rdrand.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>
#include "asmdefs.h"
#include "thread.h"

#if __linux__
#include "linux/threadlocal.h"
#endif

#define TD_FROM_TCS (4 * OE_PAGE_SIZE)

OE_STATIC_ASSERT(OE_OFFSETOF(td_t, magic) == td_magic);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, depth) == td_depth);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, host_rcx) == td_host_rcx);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, host_rsp) == td_host_rsp);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, host_rbp) == td_host_rbp);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, host_previous_rsp) == td_host_previous_rsp);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, host_previous_rbp) == td_host_previous_rbp);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, oret_func) == td_oret_func);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, oret_arg) == td_oret_arg);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, callsites) == td_callsites);
OE_STATIC_ASSERT(OE_OFFSETOF(td_t, simulate) == td_simulate);

// Static asserts for consistency with
// debugger/pythonExtension/gdb_sgx_plugin.py
#if defined(__linux__)
OE_STATIC_ASSERT(td_callsites == 0xf0);
OE_STATIC_ASSERT(OE_OFFSETOF(Callsite, ocall_context) == 0x40);
OE_STATIC_ASSERT(TD_FROM_TCS == 0x4000);
OE_STATIC_ASSERT(sizeof(oe_ocall_context_t) == (2 * sizeof(uintptr_t)));
#endif

/*
**==============================================================================
**
** oe_get_thread_data()
**
**     Gets a pointer to the thread data structure from the GS segment.
**     The td_t data structure is a concatenation of the oe_thread_data_t with
**     extended fields, and this method returns the td->base offset with as the
**     appropriate type.
**
**==============================================================================
*/

oe_thread_data_t* oe_get_thread_data()
{
    td_t* td = oe_get_td();
    return &(td->base);
}

/*
**==============================================================================
**
** td_push_callsite()
**
**     Insert the Callsite structure for the current ECALL at the
**     front of the td_t.callsites list.
**
**==============================================================================
*/

void td_push_callsite(td_t* td, Callsite* callsite)
{
    callsite->next = td->callsites;
    td->callsites = callsite;
    td->depth++;
}

/*
**==============================================================================
**
** td_pop_callsite()
**
**     Remove the Callsite structure that is at the head of the
**     td_t.callsites list.
**
**==============================================================================
*/

void td_pop_callsite(td_t* td)
{
    if (!td->callsites)
        oe_abort();

    if (td->depth == 1)
    {
        // The outermost ecall is about to return.
        // Clear the thread-local storage.
        td_clear(td);
    }
    else
    {
        // Nested ecall returning.
        td->callsites = td->callsites->next;
        --td->depth;
    }
}

/*
**==============================================================================
**
** td_from_tcs()
**
**     This function calculates the address of the td_t (thread data structure)
**     relative to the TCS (Thread Control Structure) page. The td_t resides in
**     a page pointed to by the GS (segment register). This page occurs 4 pages
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
**         | GS Segment (contains td_t) |
**         +----------------------------+
**
**     This layout is determined by the enclave builder. See:
**
**         ../host/build.c (_add_control_pages)
**
**     The GS segment register is set by the EENTER instruction and the td_t
**     page is zero filled upon initial enclave entry. Software sets the
**     contents of the td_t when it first determines that td_t.self_addr is
**     zero.
**
**==============================================================================
*/

td_t* td_from_tcs(void* tcs)
{
    return (td_t*)((uint8_t*)tcs + TD_FROM_TCS);
}

/*
**==============================================================================
**
** td_to_tcs()
**
**     Compute a TCS pointer from a td_t.
**
**==============================================================================
*/

void* td_to_tcs(const td_t* td)
{
    return (uint8_t*)td - (4 * OE_PAGE_SIZE);
}

/*
**==============================================================================
**
** oe_get_td()
**
**     Returns a pointer to the thread data structure for the current thread.
**     This structure resides in the GS segment. Offset zero of this segment
**     contains the oe_thread_data_t.self_addr field (a back pointer to the
**     structure itself). This field is zero until the structure is initialized
**     by __oe_handle_main (which happens immediately an EENTER).
**
**==============================================================================
*/

td_t* oe_get_td()
{
    td_t* td;

    asm("mov %%gs:0, %0" : "=r"(td));

    return td;
}

/*
**==============================================================================
**
** td_initialized()
**
**     Returns TRUE if this thread data structure (td_t) is initialized. An
**     initialized td_t meets the following conditions:
**
**         (1) td is not null
**         (2) td->base.self_addr == td
**         (3) td->magic == TD_MAGIC
**
**==============================================================================
*/

bool td_initialized(td_t* td)
{
    if (td && td->magic == TD_MAGIC && td->base.self_addr == (uint64_t)td)
        return true;

    return false;
}

/*
**==============================================================================
**
** td_init()
**
**     Initialize the thread data structure (td_t) if not already initialized.
**     The td_t resides in the GS segment and is located relative to the TCS.
**     Refer to the following layout.
**
**         +-------------------------+
**         | Guard Page              |
**         +-------------------------+
**         | Stack pages             |
**         +-------------------------+
**         | Guard Page              |
**         +-------------------------+
**         | TCS Page                |
**         +-------------------------+
**         | SSA (State Save Area) 0 |
**         +-------------------------+
**         | SSA (State Save Area) 1 |
**         +-------------------------+
**         | Guard Page              |
**         +-------------------------+
**         | GS page (contains td_t) |
**         +-------------------------+
**
**     Note: the host register fields are pre-initialized by oe_enter:
**
**==============================================================================
*/

void td_init(td_t* td)
{
    /* If not already initialized */
    if (!td_initialized(td))
    {
        // td_t.hostsp, td_t.hostbp, and td_t.retaddr already set by
        // oe_enter().

        /* Clear base structure */
        memset(&td->base, 0, sizeof(td->base));

        /* Set pointer to self */
        td->base.self_addr = (uint64_t)td;

        /* Set the magic number */
        td->magic = TD_MAGIC;

        /* Set the ECALL depth to zero */
        td->depth = 0;

        /* List of callsites is initially empty */
        td->callsites = NULL;

        /* initilize the stack_guard at %%fs:0x28 with a random number */
        unsigned char* fs = (unsigned char*)td + OE_PAGE_SIZE * 1;
        uint64_t* stack_guard = (uint64_t*)(fs + 0x28);
        *stack_guard = oe_rdrand();

#if __linux__
        oe_thread_local_init(td);
#endif
    }
}

/*
**==============================================================================
**
** td_clear()
**
**     Clear the td_t. This is called when the ECALL depth falls to zero
**     in td_pop_callsite().
**
**==============================================================================
*/

void td_clear(td_t* td)
{
    if (td->depth != 1)
        oe_abort();

    // Release any pthread thread-local storage created using
    // pthread_create_key.
    oe_thread_destruct_specific();

#if __linux__
    oe_thread_local_cleanup(td);
#endif

    // The call sites and depth are cleaned up after the thread-local storage is
    // cleaned up since thread-local dynamic destructors could make ocalls.
    // For such ocalls to work depth and callsites must be cleaned up here.
    td->callsites = td->callsites->next;
    --td->depth;

    /* Sanity checks */
    if (td->depth != 0 || td->callsites != NULL)
        oe_abort();

    /* Clear base structure */
    memset(&td->base, 0, sizeof(td->base));

    /* Clear the magic number */
    td->magic = 0;

    /* Never clear td_t.initialized nor host registers */
}
