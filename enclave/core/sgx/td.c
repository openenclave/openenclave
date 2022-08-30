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
#include <openenclave/internal/thread.h>
#include <openenclave/internal/utils.h>
#include "asmdefs.h"
#include "openenclave/bits/defs.h"
#include "openenclave/internal/jump.h"
#include "thread.h"
#include "threadlocal.h"

OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, magic) == td_magic);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, depth) == td_depth);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, eenter_rax) == td_eenter_rax);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, host_rcx) == td_host_rcx);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, oret_func) == td_oret_func);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, oret_arg) == td_oret_arg);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, callsites) == td_callsites);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_sgx_td_t, simulate) == td_simulate);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_sgx_td_t, host_ecall_context) == td_host_ecall_context);
OE_STATIC_ASSERT(
    OE_OFFSETOF(oe_sgx_td_t, host_previous_ecall_context) ==
    td_host_previous_ecall_context);

// !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// !!!!!!!!!!!!!!!!!!!!!!!!!!! ATTENTION !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
// THE FOLLOWING STATIC ASSERTS MUST NOT BE CHANGED.
// Linux debuggers (oegdb, oelldb) do not use `callsites` field, and instead
// rely on the stitched stack to read register values of the OCALL EEXIT frame.
// Windows debuggers, however rely on reading the register values saved in the
// callsite's jumpbuf during OCALL eexit.
// Thus `callsite` field's offset and contents (jmpbuf) are part of Windows
// debugger contract.
OE_STATIC_ASSERT(td_callsites == 0xf0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_callsite_t, jmpbuf) == 0x0);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_jmpbuf_t, rsp) == 0x00);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_jmpbuf_t, rbp) == 0x08);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_jmpbuf_t, rip) == 0x10);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_jmpbuf_t, rbx) == 0x18);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_jmpbuf_t, r12) == 0x20);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_jmpbuf_t, r13) == 0x28);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_jmpbuf_t, r14) == 0x30);
OE_STATIC_ASSERT(OE_OFFSETOF(oe_jmpbuf_t, r15) == 0x38);
OE_STATIC_ASSERT(sizeof(oe_jmpbuf_t) == 64);

// Offset of the td page from the tcs page in bytes. This varies depending on
// the size of thread-local data.
OE_EXPORT uint64_t _td_from_tcs_offset;

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
**     Insert the oe_callsite_t structure for the current ECALL at the
**     front of the oe_sgx_td_t.callsites list.
**
**==============================================================================
*/

void td_push_callsite(oe_sgx_td_t* td, oe_callsite_t* callsite)
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
**     design of this structure, the debugger needs the GS segment register
**     to find oe_sgx_td_t. Since oe_sgx_td_t is moved to current FS page, now
**     the GS segment register needs to point to this page. Do not change the GS
**     segment register until it is solved on Windows debugger.
**     !!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
**
** td_from_tcs()
**
**     This function calculates the address of the oe_sgx_td_t (thread data
**     structure) relative to the TCS (Thread Control Structure) page. The
**     oe_sgx_td_t resides in a page pointed to by the FS (segment register).
**     This page occurs 5 pages after the TCS page. The layout is as follows:
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
**     oe_sgx_td_t.self_addr is zero.
**
**==============================================================================
*/

oe_sgx_td_t* td_from_tcs(void* tcs)
{
    return (oe_sgx_td_t*)((uint8_t*)tcs + _td_from_tcs_offset);
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
    return (uint8_t*)td - _td_from_tcs_offset;
}

/*
**==============================================================================
**
** oe_sgx_get_td()
**
**     Returns a pointer to the thread data structure for the current thread.
**     This structure resides in the FS segment. Offset zero of this segment
**     contains the oe_thread_data_t.self_addr field (a back pointer to the
**     structure itself). This field is zero until the structure is initialized
**     by __oe_handle_main (which happens immediately an EENTER).
**
**==============================================================================
*/

static oe_sgx_td_t* _sgx_get_td(bool check_fs)
{
    oe_sgx_td_t* td;
    void* fsbase;
    void* gsbase;

    asm("mov %%fs:0, %0" : "=r"(fsbase));
    asm("mov %%gs:0, %0" : "=r"(gsbase));

    td = (oe_sgx_td_t*)fsbase;

    if (fsbase != gsbase)
    {
        /*
         * The mismatch between FS and GS indicates that FS could have
         * been changed by the application.
         *
         * If check_fs is set, we except the application to be responsible
         * for restoring the FS value prior to re-entering OE layer (e.g.,
         * calling an OCALL). Otherwise, abort the execution if the enclave
         * is not in simulation mode (on Windows, GS could also be changed).
         *
         * If check_fs is not set, we bypass the check and use GS as td.
         * Currently, places that need to bypass the check include:
         * 1. second-stage exception handling as we cannot the application to
         *   restore the FS before an exception.
         * 2. oe_abort as it can be invoked anywhere (including this function).
         */
        if (check_fs)
        {
            if (!(td_initialized(td) && td->simulate))
                oe_abort();

            /* Continue with FS as td in simulation mode */
        }
        else
            td = (oe_sgx_td_t*)gsbase; /* use GS as td */
    }

    return td;
}

oe_sgx_td_t* oe_sgx_get_td()
{
    return _sgx_get_td(true /* check_fs */);
}

oe_sgx_td_t* oe_sgx_get_td_no_fs_check()
{
    return _sgx_get_td(false /* check_fs */);
}

/*
**==============================================================================
**
** oe_sgx_clear_td_states()
**
**     Internal API that allows an enclave to clear the td states.
**
**==============================================================================
*/

void oe_sgx_td_clear_states(oe_sgx_td_t* td)
{
    /* Mask host signals by default */
    oe_sgx_td_mask_host_signal(td);

    /* Clear exception-related information */
    td->exception_code = 0;
    td->exception_flags = 0;
    td->exception_address = 0;
    td->faulting_address = 0;
    td->error_code = 0;
    td->last_ssa_rsp = 0;
    td->last_ssa_rbp = 0;

    /* Clear states related host signal handling */
    td->exception_nesting_level = 0;
    td->is_handling_host_signal = 0;
    td->host_signal_bitmask = 0;
    td->host_signal = 0;

    /* Clear the states of the state machine */
    td->previous_state = OE_TD_STATE_NULL;
    td->state = OE_TD_STATE_RUNNING; // the default state during the runtime
}

/*
**==============================================================================
**
** oe_sgx_td_set_exception_handler_stack()
**
**     Internal API that allows an enclave to setup stack area for
**     exception handlers to use.
**
**==============================================================================
*/
bool oe_sgx_td_set_exception_handler_stack(
    oe_sgx_td_t* td,
    void* stack,
    uint64_t size)
{
    if (!td)
        return false;

    /* ensure stack + size is 16-byte aligned */
    if (((uint64_t)stack + size) % 16)
        return false;

    td->exception_handler_stack_size = size;
    td->exception_handler_stack = (uint64_t)stack;

    return true;
}

/*
**==============================================================================
**
** oe_sgx_td_register_exception_handler_stack()
** oe_sgx_td_unregister_exception_handler_stack()
**
**     Internal APIs that allows an enclave to register or unregister
**     the exception handler stack for the given exception type
**
**==============================================================================
*/

OE_INLINE bool _td_set_exception_handler_stack_bitmask(
    oe_sgx_td_t* td,
    uint64_t type,
    bool set_bit)
{
    if (!td)
        return false;

    if (type > OE_SGX_EXCEPTION_CODE_MAXIMUM)
        return false;

    oe_spin_lock(&td->lock);

    if (set_bit)
        td->exception_handler_stack_bitmask |= 1UL << type;
    else
        td->exception_handler_stack_bitmask &= ~(1UL << type);

    oe_spin_unlock(&td->lock);

    return true;
}

bool oe_sgx_td_register_exception_handler_stack(oe_sgx_td_t* td, uint64_t type)
{
    return _td_set_exception_handler_stack_bitmask(td, type, 1 /* set */);
}

bool oe_sgx_td_unregister_exception_handler_stack(
    oe_sgx_td_t* td,
    uint64_t type)
{
    return _td_set_exception_handler_stack_bitmask(td, type, 0 /* clear */);
}

/*
**==============================================================================
**
** oe_sgx_td_exception_handler_stack_registered
**
**     Internal API for querying whether the thread registers the exception
**     handler stack for the given exception type
**
**==============================================================================
*/
bool oe_sgx_td_exception_handler_stack_registered(
    oe_sgx_td_t* td,
    uint64_t type)
{
    if (!td)
        return false;

    if (type > OE_SGX_EXCEPTION_CODE_MAXIMUM)
        return false;

    return (td->exception_handler_stack_bitmask & (1UL << type)) != 0;
}

/*
**==============================================================================
**
** oe_sgx_td_mask_host_signal()
** oe_sgx_td_unmask_host_signal()
**
**     Internal APIs that allows a thread to self-mask or unmask host signals
**
**==============================================================================
*/

OE_INLINE void _set_td_host_signal_unmasked(oe_sgx_td_t* td, uint64_t value)
{
    if (!td)
        return;

    td->host_signal_unmasked = value;
}

void oe_sgx_td_mask_host_signal(oe_sgx_td_t* td)
{
    _set_td_host_signal_unmasked(td, 0);
}

void oe_sgx_td_unmask_host_signal(oe_sgx_td_t* td)
{
    _set_td_host_signal_unmasked(td, 1);
}

/*
**==============================================================================
**
** oe_sgx_register_td_host_signal()
** oe_sgx_unregister_td_host_signal()
**
**     Internal APIs that allows an enclave to register or unregister signals
**     raised by the host for itself or a target thread
**
**==============================================================================
*/

OE_INLINE bool _set_td_host_signal_bitmask(
    oe_sgx_td_t* td,
    int signal_number,
    bool set_bit)
{
    if (!td)
        return false;

    /* only allow number 1-64 */
    if (signal_number <= 0 || signal_number > 64)
        return false;

    oe_spin_lock(&td->lock);

    if (set_bit)
        td->host_signal_bitmask |= 1UL << (signal_number - 1);
    else
        td->host_signal_bitmask &= ~(1UL << (signal_number - 1));

    oe_spin_unlock(&td->lock);

    return true;
}

bool oe_sgx_td_register_host_signal(oe_sgx_td_t* td, int signal_number)
{
    return _set_td_host_signal_bitmask(td, signal_number, 1 /* set */);
}

bool oe_sgx_td_unregister_host_signal(oe_sgx_td_t* td, int signal_number)
{
    return _set_td_host_signal_bitmask(td, signal_number, 0 /* clear */);
}

/*
**==============================================================================
**
** oe_sgx_td_host_signal_registered
**
**     Internal API for querying whether the thread registers the given
**     host signal
**
**==============================================================================
*/
bool oe_sgx_td_host_signal_registered(oe_sgx_td_t* td, int signal_number)
{
    if (!td)
        return false;

    /* only allow number 1-64 */
    if (signal_number <= 0 || signal_number > 64)
        return false;

    return (td->host_signal_bitmask & (1UL << (signal_number - 1))) != 0;
}

/*
**==============================================================================
**
** oe_sgx_td_is_handling_host_signal()
**
**     Internal API for querying whether the thread is handling a host signal
**
**==============================================================================
*/

bool oe_sgx_td_is_handling_host_signal(oe_sgx_td_t* td)
{
    if (!td)
        return false;

    return td->is_handling_host_signal;
}

/*
**==============================================================================
**
** td_initialized()
**
**     Returns TRUE if this thread data structure (oe_sgx_td_t) is initialized.
**
**     An initialized oe_sgx_td_t meets the following conditions:
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
