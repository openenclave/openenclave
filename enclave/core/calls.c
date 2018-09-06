// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/atexit.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/fault.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/hostalloc.h>
#include <openenclave/internal/jump.h>
#include <openenclave/internal/malloc.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/reloc.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "../report.h"
#include "asmdefs.h"
#include "cpuid.h"
#include "init.h"
#include "report.h"
#include "td.h"
#include "thread.h"

uint64_t __oe_enclave_status = OE_OK;
uint8_t __oe_initialized = 0;

/* If true, disable the debug malloc checking */
bool oe_disable_debug_malloc_check;

/*
**==============================================================================
**
** Glossary:
**
**     TCS      - Thread control structure. The TCS is an address passed to
**                EENTER and passed onto the entry point (_start). The TCS
**                is the address of a TCS page in the enclave memory. This page
**                is not accessible to the enclave itself. The enclave stores
**                state about the execution of a thread in this structure,
**                such as the entry point (TCS.oentry), which refers to the
**                _start function. It also maintains the index of the
**                current SSA (TCS.cssa) and the number of SSA's (TCS.nssa).
**
**     TD       - Thread data. Per thread data as defined by the
**                oe_thread_data_t structure and extended by the TD structure.
**                This structure records the stack pointer of the last EENTER.
**
**     SP       - Stack pointer. Refers to the enclave's stack pointer.
**
**     BP       - Base pointer. Refers to the enclave's base pointer.
**
**     HOSTSP   - Host stack pointer. Refers to the host's stack pointer as
**                received in the EENTER call.
**
**     HOSTBP   - Host base pointer. Refers to the host's base pointer as
**                received in the EENTER call.
**
**     AEP      - Asynchronous Exception Procedure. This procedure is passed
**                by the host to EENTER. If a fault occurs while in the enclave,
**                the hardware calls this procedure. The procedure may
**                terminate or call ERESUME to continue executing in the
**                enclave.
**
**     AEX      - Asynchronous Exception (occurs when enclave faults). The
**                hardware transfers control to a host AEP (passed as a
**                parameter to EENTER).
**
**     SSA      - State Save Area. When a fault occurs in the enclave, the
**                hardware saves the state here (general purpose registers)
**                and then transfers control to the host AEP. If the AEP
**                executes the ERESUME instruction, the hardware restores the
**                state from the SSA.
**
**     EENTER   - An untrusted instruction that is executed by the host to
**                enter the enclave. The caller passes the address of a TCS page
**                within the enclave, an AEP, and any parameters in the RDI and
**                RSI registers. This implementation passes the operation
**                number (FUNC) in RDI and a pointer to the arguments structure
**                (ARGS) in RSI.
**
**     EEXIT    - An instruction that is executed by the host to exit the
**                enclave and return control to the host. The caller passes
**                the address of some instruction to jump to (RETADDR) in the
**                RBX register and an AEP in the RCX register (null at this
**                time).
**
**     RETADDR  - Refers to the address of the return instruction that the
**                hardware jumps to from EEXIT. This is an instruction in
**                host immediately following the instruction that executed
**                EENTER.
**
**     CSSA     - The current SSA slot index (as given by TCS.cssa). EENTER
**                passes a CSSA parameter (RAX) to _start(). A CSSA of zero
**                indicates a normal entry. A non-zero CSSA indicates an
**                exception entry (an AEX has occurred).
**
**     NSSA     - The number of SSA slots in the thread section (of this
**                enclave. If CSSA == NSSA, then the SSA's have been exhausted
**                and the EENTER instruction will fault.
**
**     ECALL    - A function call initiated by the host and carried out by
**                the enclave. The host executes the EENTER instruction to
**                enter the enclave.
**
**     ERET     - A return from an ECALL initiated by the enclave. The
**                enclave executes the EEXIT instruction to exit the enclave.
**
**     OCALL    - A function call initiated by the enclave and carried out
**                by the host. The enclave executes the EEXIT instruction to
**                exit the enclave.
**
**     ORET     - A return from an OCALL initiated by the host. The host
**                executes the EENTER instruction to enter the enclave.
**
**==============================================================================
*/

/*
**==============================================================================
**
** _HandleInitEnclave()
**
**     Handle the OE_ECALL_INIT_ENCLAVE from host and ensures that each state
**     initialization function in the enclave only runs once.
**
**==============================================================================
*/
static oe_result_t _HandleInitEnclave(uint64_t argIn)
{
    static bool _once = false;
    oe_result_t result = OE_OK;
    /* Double checked locking (DCLP). */
    bool o = _once;

    /* DCLP Acquire barrier. */
    OE_ATOMIC_MEMORY_BARRIER_ACQUIRE();
    if (o == false)
    {
        if (!oe_is_outside_enclave(
                (void*)argIn, sizeof(oe_init_enclave_args_t)))
        {
            OE_THROW(OE_INVALID_PARAMETER);
        }

        static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;
        oe_spin_lock(&_lock);

        if (_once == false)
        {
            /* Set the global enclave handle */
            if (argIn)
            {
                oe_init_enclave_args_t* args = (oe_init_enclave_args_t*)argIn;
                oe_init_enclave_args_t safe_args;

                if (!oe_is_outside_enclave(args, sizeof(*args)))
                    OE_THROW(OE_INVALID_PARAMETER);

                /* Copy structure into enclave memory */
                safe_args = *args;

                if (!oe_is_outside_enclave(safe_args.enclave, 1))
                    OE_THROW(OE_INVALID_PARAMETER);

                oe_enclave = safe_args.enclave;
            }

            /* Call all enclave state initialization functions */
            oe_initialize_cpuid(argIn);

            /* Call global constructors. Now they can safely use simulated
             * instructions like CPUID. */
            oe_call_init_functions();

            /* DCLP Release barrier. */
            OE_ATOMIC_MEMORY_BARRIER_RELEASE();
            _once = true;
            __oe_initialized = 1;
        }

        oe_spin_unlock(&_lock);
    }
OE_CATCH:
    return result;
}

/*
**==============================================================================
**
** _HandleCallEnclave()
**
**     This function handles a high-level enclave call.
**
**==============================================================================
*/

/* Get ECALL pages, check that ECALL pages are valid, and cache. */
static const oe_ecall_pages_t* _GetECallPages()
{
    static const oe_ecall_pages_t* pages;

    if (!pages)
    {
        pages = (const oe_ecall_pages_t*)__oe_get_ecall_base();
        if (pages->magic != OE_ECALL_PAGES_MAGIC)
            oe_abort();
    }
    return pages;
}

static oe_result_t _HandleCallEnclave(uint64_t argIn)
{
    oe_call_enclave_args_t args, *argsPtr;
    oe_result_t result = OE_OK;
    uint64_t vaddr;
    const oe_ecall_pages_t* ecallPages = _GetECallPages();

    if (!oe_is_outside_enclave((void*)argIn, sizeof(oe_call_enclave_args_t)))
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }
    argsPtr = (oe_call_enclave_args_t*)argIn;
    args = *argsPtr;

    if (!args.vaddr || (args.func >= ecallPages->num_vaddrs) ||
        ((vaddr = ecallPages->vaddrs[args.func]) != args.vaddr))
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Translate function address from virtual to real address */
    {
        oe_enclave_func_t func =
            (oe_enclave_func_t)((uint64_t)__oe_get_enclave_base() + vaddr);
        func(args.args);
    }

    argsPtr->result = OE_OK;

OE_CATCH:
    return result;
}

/*
**==============================================================================
**
** _HandleExit()
**
**     Initiate call to EEXIT.
**
**==============================================================================
*/

static void _HandleExit(oe_code_t code, uint16_t func, uint64_t arg)
{
    oe_exit(oe_make_call_arg1(code, func, 0, OE_OK), arg);
}

void _oe_virtual_exception_dispatcher(TD* td, uint64_t argIn, uint64_t* argOut);

/*
**==============================================================================
**
** _HandleECall()
**
**     Handle an ECALL.
**
**==============================================================================
*/

static void _HandleECall(
    TD* td,
    uint16_t func,
    uint64_t argIn,
    uint64_t* outputArg1,
    uint64_t* outputArg2)
{
    oe_result_t result = OE_OK;

    /* Insert ECALL context onto front of TD.ecalls list */
    Callsite callsite;
    uint64_t argOut = 0;

    oe_memset(&callsite, 0, sizeof(callsite));
    TD_PushCallsite(td, &callsite);

    // Acquire release semantics for __oe_initialized are present in
    // _HandleInitEnclave.
    if (!__oe_initialized)
    {
        // The first call to the enclave must be to initialize it.
        // Global constructors can throw exceptions/signals and result in signal
        // handlers being invoked. Eg. Using CPUID instruction within a global
        // constructor. We should also allow handling these exceptions.
        if (func != OE_ECALL_INIT_ENCLAVE &&
            func != OE_ECALL_VIRTUAL_EXCEPTION_HANDLER)
        {
            goto done;
        }
    }
    else
    {
        // Disallow re-initialization.
        if (func == OE_ECALL_INIT_ENCLAVE)
        {
            goto done;
        }
    }

    // TD_PushCallsite increments the depth. depth > 1 indicates a reentrant
    // call. Reentrancy is allowed to handle exceptions and to terminate the
    // enclave.
    if (td->depth > 1 && (func != OE_ECALL_VIRTUAL_EXCEPTION_HANDLER &&
                          func != OE_ECALL_DESTRUCTOR))
    {
        /* reentrancy not permitted. */
        result = OE_REENTRANT_ECALL;
        goto done;
    }

    /* Dispatch the ECALL */
    switch (func)
    {
        case OE_ECALL_CALL_ENCLAVE:
        {
            argOut = _HandleCallEnclave(argIn);
            break;
        }
        case OE_ECALL_DESTRUCTOR:
        {
            /* Call functions installed by __cxa_atexit() and oe_atexit() */
            oe_call_at_exit_functions();

            /* Call all finalization functions */
            oe_call_fini_functions();

#if defined(OE_USE_DEBUG_MALLOC)

            /* If memory still allocated, print a trace and return an error */
            if (!oe_disable_debug_malloc_check && oe_debug_malloc_check() != 0)
                result = OE_MEMORY_LEAK;

#endif /* defined(OE_USE_DEBUG_MALLOC) */

            break;
        }
        case OE_ECALL_VIRTUAL_EXCEPTION_HANDLER:
        {
            _oe_virtual_exception_dispatcher(td, argIn, &argOut);
            break;
        }
        case OE_ECALL_INIT_ENCLAVE:
        {
            argOut = _HandleInitEnclave(argIn);
            break;
        }
        case OE_ECALL_GET_SGX_REPORT:
        {
            argOut = _HandleGetSgxReport(argIn);
            break;
        }
        case OE_ECALL_VERIFY_REPORT:
        {
            oe_handle_verify_report(argIn, &argOut);
            break;
        }
        default:
        {
            /* No function found with the number */
            result = OE_NOT_FOUND;
            goto done;
        }
    }

done:

    // Release any thread-specific-data for this thread if returning from
    // a non-nested ECALL.
    if (td->depth == 1)
        oe_thread_destruct_specific();

    /* Remove ECALL context from front of TD.ecalls list */
    TD_PopCallsite(td);

    /* Perform ERET, giving control back to host */
    *outputArg1 = oe_make_call_arg1(OE_CODE_ERET, func, 0, result);
    *outputArg2 = argOut;
}

/*
**==============================================================================
**
** _HandleORET()
**
**     Handle an OCALL return.
**
**==============================================================================
*/

OE_INLINE void _HandleORET(TD* td, uint16_t func, uint16_t result, int64_t arg)
{
    Callsite* callsite = td->callsites;

    if (!callsite)
        return;

    td->oret_func = func;
    td->oret_result = result;
    td->oret_arg = arg;

    oe_longjmp(&callsite->jmpbuf, 1);
}

/*
**==============================================================================
**
** oe_ocall()
**
**     Initiate a call into the host (exiting the enclave).
**
**==============================================================================
*/

oe_result_t oe_ocall(uint16_t func, uint64_t argIn, uint64_t* argOut)
{
    oe_result_t result = OE_UNEXPECTED;
    TD* td = oe_get_td();
    Callsite* callsite = td->callsites;

    /* If the enclave is in crashing/crashed status, new OCALL should fail
    immediately. */
    if (__oe_enclave_status != OE_OK)
        OE_THROW((oe_result_t)__oe_enclave_status);

    /* Check for unexpected failures */
    if (!callsite)
        OE_THROW(OE_UNEXPECTED);

    /* Check for unexpected failures */
    if (!TD_Initialized(td))
        OE_THROW(OE_FAILURE);

    /* Save call site where execution will resume after OCALL */
    if (oe_setjmp(&callsite->jmpbuf) == 0)
    {
        /* Exit, giving control back to the host so it can handle OCALL */
        _HandleExit(OE_CODE_OCALL, func, argIn);

        /* Unreachable! Host will transfer control back to oe_enter() */
        oe_abort();
    }
    else
    {
        OE_TRY(result = (oe_result_t)td->oret_result);

        if (argOut)
            *argOut = td->oret_arg;

        /* ORET here */
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

/*
**==============================================================================
**
** oe_call_host()
**
**==============================================================================
*/

oe_result_t oe_call_host(const char* func, void* argsIn)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_host_args_t* args = NULL;

    /* Reject invalid parameters */
    if (!func)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize the arguments */
    {
        size_t len = oe_strlen(func);

        if (!(args = oe_host_alloc_for_call_host(
                  sizeof(oe_call_host_args_t) + len + 1)))
        {
            /* If the enclave is in crashing/crashed status, new OCALL should
             * fail immediately. */
            OE_TRY(__oe_enclave_status);
            OE_THROW(OE_OUT_OF_MEMORY);
        }

        oe_memcpy(args->func, func, len + 1);

        args->args = argsIn;
        args->result = OE_UNEXPECTED;
    }

    /* Call into the host */
    OE_TRY(oe_ocall(OE_OCALL_CALL_HOST, (int64_t)args, NULL));

    /* Check the result */
    OE_TRY(args->result);

    result = OE_OK;

OE_CATCH:
    oe_host_free_for_call_host(args);
    return result;
}

/*
**==============================================================================
**
** oe_call_host_by_address()
**
**==============================================================================
*/

oe_result_t oe_call_host_by_address(
    void (*func)(void*, oe_enclave_t*),
    void* argsIn)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_host_by_address_args_t* args = NULL;

    /* Reject invalid parameters */
    if (!func)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Verify that the function address is outside the enclave */
    if (!oe_is_outside_enclave(func, sizeof(func)))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize the arguments */
    {
        if (!(args = oe_host_alloc_for_call_host(sizeof(*args))))
        {
            /* Fail if the enclave is crashing. */
            OE_TRY(__oe_enclave_status);
            OE_THROW(OE_OUT_OF_MEMORY);
        }

        args->args = argsIn;
        args->func = func;
        args->result = OE_UNEXPECTED;
    }

    /* Call the host function with this address */
    OE_TRY(oe_ocall(OE_OCALL_CALL_HOST_BY_ADDRESS, (int64_t)args, NULL));

    /* Check the result */
    OE_TRY(args->result);

    result = OE_OK;

OE_CATCH:

    oe_host_free_for_call_host(args);

    return result;
}

/*
**==============================================================================
**
** __oe_handle_main()
**
**     This function is called by oe_enter(), which is called by the EENTER
**     instruction (executed by the host). The host passes the following
**     parameters to EENTER:
**
**         RBX - TCS - address of a TCS page in the enclave
**         RCX - AEP - pointer to host's asynchronous exception procedure
**         RDI - ARGS1 (holds the CODE and FUNC parameters)
**         RSI - ARGS2 (holds the pointer to the args structure)
**
**     EENTER then calls oe_enter() with the following registers:
**
**         RAX - CSSA - index of current SSA
**         RBX - TCS - address of TCS
**         RCX - RETADDR - address to jump back to on EEXIT
**         RDI - ARGS1 (holds the code and func parameters)
**         RSI - ARGS2 (holds the pointer to the args structure)
**
**     Finally oe_enter() calls this function with the following parameters:
**
**         ARGS1 (holds the code and func parameters)
**         ARGS2 (holds the pointer to the args structure)
**         CSSA - index of current SSA
**         TCS - address of TCS (thread control structure)
**
**     Each enclave contains one or more thread sections (a collection of pages
**     used by a thread entering the enclave). Each thread section has the
**     following layout:
**
**         +--------------------------------+
**         | Guard Page                     |
**         +--------------------------------+
**         | Stack pages                    |
**         +--------------------------------+
**         | Guard Page                     |
**         +--------------------------------+
**         | TCS Page                       |
**         +--------------------------------+
**         | SSA (State Save Area) 0        |
**         +--------------------------------+
**         | SSA (State Save Area) 1        |
**         +--------------------------------+
**         | Guard Page                     |
**         +--------------------------------+
**         | GS page (contains thread data) |
**         +--------------------------------+
**
**     EENTER sets the GS segment register to refer to the GS page before
**     calling this function.
**
**     If the enclave should fault, SGX saves the registers in the SSA slot
**     (given by CSSA) and invokes the host's asynchronous exception handler
**     (AEP). The handler may terminate or call ERESUME which increments CSSA
**     and enters this function again. So:
**
**         CSSA == 0: indicates a normal entry
**         CSSA >= 1: indicates an exception entry
**
**     Since the enclave builder only allocates two SSA pages, the enclave can
**     nest no more than two faults. EENTER fails when the number of SSA slots
**     are exhausted (i.e., TCS.CSSA == TCS.NSSA)
**
**     This function ultimately calls EEXIT to exit the enclave. An enclave may
**     exit to the host for two reasons (aside from an asynchronous exception
**     already mentioned):
**
**         (1) To return normally from an ECALL
**         (2) To initiate an OCALL
**
**     When exiting to perform an OCALL, the host may perform another ECALL,
**     and so ECALLS and OCALLS may be nested arbitrarily until stack space is
**     exhausted (hitting a guard page). The state for performing nested calls
**     is maintained on the stack associated with the TCS (see diagram above).
**
**     The enclave's stack pointer is determined as follows:
**
**         (*) For non-nested calls, the stack pointer is calculated relative
**             to the TCS (one page before minus the STATIC stack size).
**
**         (*) For nested calls the stack pointer is obtained from the
**             TD.last_sp field (saved by the previous call).
**
**==============================================================================
*/
void __oe_handle_main(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t cssa,
    void* tcs,
    uint64_t* outputArg1,
    uint64_t* outputArg2)
{
    oe_code_t code = oe_get_code_from_call_arg1(arg1);
    uint16_t func = oe_get_func_from_call_arg1(arg1);
    uint16_t arg1_result = oe_get_result_from_call_arg1(arg1);
    uint64_t argIn = arg2;
    *outputArg1 = 0;
    *outputArg2 = 0;

    // Block enclave enter based on current enclave status.
    switch (__oe_enclave_status)
    {
        case OE_OK:
        {
            break;
        }
        case OE_ENCLAVE_ABORTING:
        {
            // Block any ECALL except first time OE_ECALL_DESTRUCTOR call.
            // Don't block ORET here.
            if (code == OE_CODE_ECALL)
            {
                if (func == OE_ECALL_DESTRUCTOR)
                {
                    // Termination function should be only called once.
                    __oe_enclave_status = OE_ENCLAVE_ABORTED;
                }
                else
                {
                    // Return crashing status.
                    *outputArg1 =
                        oe_make_call_arg1(OE_CODE_ERET, func, 0, OE_OK);
                    *outputArg2 = __oe_enclave_status;
                    return;
                }
            }

            break;
        }
        default:
        {
            // Return crashed status.
            *outputArg1 = oe_make_call_arg1(OE_CODE_ERET, func, 0, OE_OK);
            *outputArg2 = OE_ENCLAVE_ABORTED;
            return;
        }
    }

    // Initialize the enclave the first time it is ever entered. Note that
    // this function DOES NOT call global constructors. Global construction
    // is performed while handling OE_ECALL_INIT_ENCLAVE.
    oe_initialize_enclave();

    /* Get pointer to the thread data structure */
    TD* td = TD_FromTCS(tcs);

    /* Initialize thread data structure (if not already initialized) */
    if (!TD_Initialized(td))
        TD_Init(td);

    /* If this is a normal (non-exception) entry */
    if (cssa == 0)
    {
        switch (code)
        {
            case OE_CODE_ECALL:
                _HandleECall(td, func, argIn, outputArg1, outputArg2);
                break;

            case OE_CODE_ORET:
                /* Eventually calls oe_exit() and never returns here if
                 * successful */
                _HandleORET(td, func, arg1_result, argIn);
            // fallthrough

            default:
                /* Unexpected case */
                oe_abort();
        }
    }
    else /* cssa > 0 */
    {
        if ((code == OE_CODE_ECALL) &&
            (func == OE_ECALL_VIRTUAL_EXCEPTION_HANDLER))
        {
            _HandleECall(td, func, argIn, outputArg1, outputArg2);
            return;
        }

        /* ATTN: handle asynchronous exception (AEX) */
        oe_abort();
    }
}

/*
**==============================================================================
**
** _oe_notify_nested_exit_start()
**
**     Notify the nested exist happens.
**
**     This function saves the current ocall context to the thread data. The
**     ocall context contains the stack pointer and the return address of the
**     function when ocall happens inside enclave (i.e. one type of nested
**     exit).
**     When debugger does stack stitching, it will update the untrusted ocall
**     frame's previous stack frame pointer and return address with the ocall
**     context from trusted thread data. When GDB does stack walking, the parent
**     stack of an untrusted ocall will be stack of the _OE_EXIT trusted
**     function instead of stack of oe_enter/__morestack untrusted function.
**     Refer to the _oe_notify_ocall_start function in host side, and the
**     OCallStartBreakpoint and update_untrusted_ocall_frame function in the
**     python plugin.
**
**==============================================================================
*/
void _oe_notify_nested_exit_start(
    uint64_t arg1,
    oe_ocall_context_t* ocallContext)
{
    // Check if it is an OCALL.
    oe_code_t code = oe_get_code_from_call_arg1(arg1);
    if (code != OE_CODE_OCALL)
        return;

    // Save the ocallcontext to the callsite of current enclave thread.
    TD* td = oe_get_td();
    Callsite* callsite = td->callsites;
    callsite->ocallContext = ocallContext;

    return;
}

void oe_abort(void)
{
    // Once it starts to crash, the state can only transit forward, not
    // backward.
    if (__oe_enclave_status < OE_ENCLAVE_ABORTING)
    {
        __oe_enclave_status = OE_ENCLAVE_ABORTING;
    }

    // Return to the latest ECALL.
    _HandleExit(OE_CODE_ERET, 0, __oe_enclave_status);
    return;
}
