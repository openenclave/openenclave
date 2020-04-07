// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

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
#include "td.h"
#include "thread.h"

#if __linux__
#include "linux/threadlocal.h"
#endif

/*
**==============================================================================
**
** td_pop_callsite()
**
**     Remove the Callsite structure that is at the head of the
**     oe_sgx_td_t.callsites list.
**
**==============================================================================
*/

void td_pop_callsite(oe_sgx_td_t* td)
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
** td_init()
**
**     Initialize the thread data structure (oe_sgx_td_t) if not already
*initialized.
**     The oe_sgx_td_t resides in the FS segment and is located relative to the
*TCS.
**     Refer to the following layout.
**
**         +----------------------------+
**         | Guard Page                 |
**         +----------------------------+
**         | Stack pages                |
**         +----------------------------+
**         | Guard Page                 |
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
**     Note: the host register fields are pre-initialized by oe_enter:
**
**==============================================================================
*/

void td_init(oe_sgx_td_t* td)
{
    /* If not already initialized */
    if (!td_initialized(td))
    {
        // oe_sgx_td_t.hostsp, oe_sgx_td_t.hostbp, and oe_sgx_td_t.retaddr
        // already set by oe_enter().

        /* Clear base structure */
        memset(&td->base, 0, sizeof(td->base));

        /* Set pointer to self */
        td->base.self_addr = (uint64_t)td;

        /* initialize the stack_guard at %%fs:0x28 with a random number.
        oe_rdrand is a warpper of rdrand. rdrand is a hardware-implemented
        Pseudo Random Generator, and it is repeatedly seeeded by a high entropy
        source. */
        td->base.stack_guard = oe_rdrand();

        /* Set the magic number */
        td->magic = TD_MAGIC;

        /* Set the ECALL depth to zero */
        td->depth = 0;

        /* List of callsites is initially empty */
        td->callsites = NULL;

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
**     Clear the oe_sgx_td_t. This is called when the ECALL depth falls to zero
**     in td_pop_callsite().
**
**==============================================================================
*/

void td_clear(oe_sgx_td_t* td)
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

    /* Never clear oe_sgx_td_t.initialized nor host registers */
}
