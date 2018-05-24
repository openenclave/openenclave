// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/atexit.h>
#include <openenclave/bits/calls.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/fault.h>
#include <openenclave/bits/globals.h>
#include <openenclave/bits/jump.h>
#include <openenclave/bits/reloc.h>
#include <openenclave/bits/sgxtypes.h>
#include <openenclave/bits/trace.h>
#include <openenclave/bits/utils.h>
#include <openenclave/enclave.h>
#include "asmdefs.h"
#include "cpuid.h"
#include "init.h"
#include "report.h"
#include "td.h"

typedef unsigned long long WORD;

#define WORD_SIZE sizeof(WORD)

uint64_t __oe_enclave_status = OE_OK;

/*
**==============================================================================
**
** Glossary:
**
**     TCS      - Thread control structure. The TCS is an address passed to
**                EENTER and passed onto the entry point (OE_Main). The TCS
**                is the address of a TCS page in the enclave memory. This page
**                is not accessible to the enclave itself. The enclave stores
**                state about the execution of a thread in this structure,
**                such as the entry point (TCS.oentry), which refers to the
**                OE_Main function. It also maintains the index of the
**                current SSA (TCS.cssa) and the number of SSA's (TCS.nssa).
**
**     TD       - Thread data. Per thread data as defined by the OE_ThreadData
**                structure and extended by the TD structure. This structure
**                records the stack pointer of the last EENTER.
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
**                passes a CSSA parameter (RAX) to OE_Main(). A CSSA of zero
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
**     Handle the OE_FUNC_INIT_ENCLAVE from host and ensures that each state
**     initialization function in the enclave only runs once.
**
**==============================================================================
*/
void _HandleInitEnclave(uint64_t argIn)
{
    static bool _once = false;

    /* Double checked locking (DCLP). */
    bool o = _once;

    /* DCLP Acquire barrier. */
    OE_ATOMIC_MEMORY_BARRIER_ACQUIRE();
    if (o == false)
    {
        static OE_Spinlock _lock = OE_SPINLOCK_INITIALIZER;
        OE_SpinLock(&_lock);

        if (_once == false)
        {
            /* Call all enclave state initialization functions */
            OE_InitializeCpuid(argIn);

            /* DCLP Release barrier. */
            OE_ATOMIC_MEMORY_BARRIER_RELEASE();
            _once = true;
        }

        OE_SpinUnlock(&_lock);
    }
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
static const OE_ECallPages* _GetECallPages()
{
    static const OE_ECallPages* pages;

    if (!pages)
    {
        pages = (const OE_ECallPages*)__OE_GetECallBase();
        if (pages->magic != OE_ECALL_PAGES_MAGIC)
            OE_Abort();
    }
    return pages;
}

static OE_Result _HandleCallEnclave(uint64_t argIn)
{
    OE_CallEnclaveArgs args, *argsPtr;
    OE_Result result = OE_OK;
    uint64_t vaddr;
    const OE_ECallPages* ecallPages = _GetECallPages();

    if (!OE_IsOutsideEnclave((void*)argIn, sizeof(OE_CallEnclaveArgs)))
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }
    argsPtr = (OE_CallEnclaveArgs*)argIn;
    args = *argsPtr;

    if (!args.vaddr || (args.func >= ecallPages->num_vaddrs) ||
        ((vaddr = ecallPages->vaddrs[args.func]) != args.vaddr))
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Translate function address from virtual to real address */
    {
        OE_EnclaveFunc func =
            (OE_EnclaveFunc)((uint64_t)__OE_GetEnclaveBase() + vaddr);
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

static void _HandleExit(OE_Code code, long func, uint64_t arg)
{
    OE_Exit(OE_MakeCallArg1(code, func, 0), arg);
}

/*
**==============================================================================
**
** OE_RegisterECall()
**
**     Register the given ECALL function, associate it with the given function
**     number.
**
**==============================================================================
*/

static OE_ECallFunction _ecalls[OE_MAX_ECALLS];
static OE_Spinlock _ecalls_spinlock = OE_SPINLOCK_INITIALIZER;

OE_Result OE_RegisterECall(uint32_t func, OE_ECallFunction ecall)
{
    OE_Result result = OE_UNEXPECTED;
    OE_SpinLock(&_ecalls_spinlock);

    if (func >= OE_MAX_ECALLS)
        OE_THROW(OE_OUT_OF_RANGE);

    if (_ecalls[func])
        OE_THROW(OE_ALREADY_IN_USE);

    _ecalls[func] = ecall;

    result = OE_OK;

OE_CATCH:
    OE_SpinUnlock(&_ecalls_spinlock);
    return result;
}

void _OE_VirtualExceptionDispatcher(TD* td, uint64_t argIn, uint64_t* argOut);

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
    uint32_t func,
    uint64_t argIn,
    uint64_t* outputArg1,
    uint64_t* outputArg2)
{
    /* Insert ECALL context onto front of TD.ecalls list */
    Callsite callsite;
    uint64_t argOut = 0;

    OE_Memset(&callsite, 0, sizeof(callsite));
    TD_PushCallsite(td, &callsite);

    /*
     * Call all global initializer functions on the first call. To support
     * OCalls from global initializers, this needs to be done after the
     * callsite has been pushed, otherwise, they could have been invoked as
     * part of consolidated init-code in __OE_HandleMain().
     */
    {
        static OE_OnceType _once = OE_ONCE_INITIALIZER;
        OE_Once(&_once, OE_CallInitFunctions);
    }

    /* Are ecalls permitted? */
    if (td->ocall_flags & OE_OCALL_FLAG_NOT_REENTRANT)
    {
        /* ecalls not permitted. */
        argOut = OE_UNEXPECTED;
        goto Exit;
    }

    /* Dispatch the ECALL */
    switch (func)
    {
        case OE_FUNC_CALL_ENCLAVE:
        {
            argOut = _HandleCallEnclave(argIn);
            break;
        }
        case OE_FUNC_DESTRUCTOR:
        {
            /* Call functions installed by __cxa_atexit() and OE_AtExit() */
            OE_CallAtExitFunctions();

            /* Call all finalization functions */
            OE_CallFiniFunctions();
            break;
        }
        case OE_FUNC_VIRTUAL_EXCEPTION_HANDLER:
        {
            _OE_VirtualExceptionDispatcher(td, argIn, &argOut);
            break;
        }
        case OE_FUNC_INIT_ENCLAVE:
        {
            _HandleInitEnclave(argIn);
            break;
        }
        case OE_FUNC_GET_REPORT:
        {
            argOut = _HandleGetReport(argIn);
            break;
        }
        default:
        {
            /* Dispatch user-registered ECALLs */
            if (func < OE_MAX_ECALLS)
            {
                OE_SpinLock(&_ecalls_spinlock);
                OE_ECallFunction ecall = _ecalls[func];
                OE_SpinUnlock(&_ecalls_spinlock);

                if (ecall)
                    ecall(argIn, &argOut);
            }
            break;
        }
    }

Exit:
    /* Remove ECALL context from front of TD.ecalls list */
    TD_PopCallsite(td);

    /* Perform ERET, giving control back to host */
    *outputArg1 = OE_MakeCallArg1(OE_CODE_ERET, func, 0);
    *outputArg2 = argOut;
    return;
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

static __inline__ void _HandleORET(TD* td, long func, long arg)
{
    Callsite* callsite = td->callsites;

    if (!callsite)
        return;

    td->oret_func = func;
    td->oret_arg = arg;

    OE_Longjmp(&callsite->jmpbuf, 1);
}

/*
**==============================================================================
**
** OE_OCall()
**
**     Initiate a call into the host (exiting the enclave).
**
**==============================================================================
*/

OE_Result OE_OCall(
    uint32_t func,
    uint64_t argIn,
    uint64_t* argOut,
    uint32_t ocall_flags)
{
    OE_Result result = OE_UNEXPECTED;
    TD* td = TD_Get();
    Callsite* callsite = td->callsites;
    uint32_t old_ocall_flags = td->ocall_flags;

    /* If the enclave is in crashing/crashed status, new OCALL should fail
    immediately. */
    if (__oe_enclave_status != OE_OK)
        OE_THROW((OE_Result)__oe_enclave_status);

    /* Check for unexpected failures */
    if (!callsite)
        OE_THROW(OE_UNEXPECTED);

    /* Check for unexpected failures */
    if (!TD_Initialized(td))
        OE_THROW(OE_FAILURE);

    td->ocall_flags |= ocall_flags;

    /* Save call site where execution will resume after OCALL */
    if (OE_Setjmp(&callsite->jmpbuf) == 0)
    {
        /* Exit, giving control back to the host so it can handle OCALL */
        _HandleExit(OE_CODE_OCALL, func, argIn);

        /* Unreachable! Host will transfer control back to OE_Main() */
        OE_Abort();
    }
    else
    {
        if (argOut)
            *argOut = td->oret_arg;

        /* ORET here */
    }

    td->ocall_flags = old_ocall_flags;

    result = OE_OK;

OE_CATCH:
    return result;
}

/*
**==============================================================================
**
** OE_CallHost()
**
**==============================================================================
*/

OE_Result OE_CallHost(const char* func, void* argsIn)
{
    OE_Result result = OE_UNEXPECTED;
    OE_CallHostArgs* args = NULL;

    /* Reject invalid parameters */
    if (!func)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize the arguments */
    {
        size_t len = OE_Strlen(func);

        if (!(args =
                  OE_HostAllocForCallHost(sizeof(OE_CallHostArgs) + len + 1)))
        {
            /* If the enclave is in crashing/crashed status, new OCALL should
             * fail immediately. */
            OE_TRY(__oe_enclave_status);
            OE_THROW(OE_OUT_OF_MEMORY);
        }

        OE_Memcpy(args->func, func, len + 1);

        args->args = argsIn;
        args->result = OE_UNEXPECTED;
    }

    /* Call into the host */
    OE_TRY(OE_OCall(OE_FUNC_CALL_HOST, (long)args, NULL, 0));

    /* Check the result */
    OE_TRY(args->result);

    result = OE_OK;

OE_CATCH:
    OE_HostFreeForCallHost(args);
    return result;
}

/*
**==============================================================================
**
** __OE_HandleMain()
**
**     This function is called by OE_Main(), which is called by the EENTER
**     instruction (executed by the host). The host passes the following
**     parameters to EENTER:
**
**         RBX - TCS - address of a TCS page in the enclave
**         RCX - AEP - pointer to host's asynchronous exception procedure
**         RDI - ARGS1 (holds the CODE and FUNC parameters)
**         RSI - ARGS2 (holds the pointer to the args structure)
**
**     EENTER then calls OE_Main() with the following registers:
**
**         RAX - CSSA - index of current SSA
**         RBX - TCS - address of TCS
**         RCX - RETADDR - address to jump back to on EEXIT
**         RDI - ARGS1 (holds the code and func parameters)
**         RSI - ARGS2 (holds the pointer to the args structure)
**
**     Finally OE_Main() calls this function with the following parameters:
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
void __OE_HandleMain(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t cssa,
    void* tcs,
    uint64_t* outputArg1,
    uint64_t* outputArg2)
{
    OE_Code code = OE_GetCodeFromCallArg1(arg1);
    uint32_t func = OE_GetFuncFromCallArg1(arg1);
    uint64_t argIn = arg2;
    *outputArg1 = 0;
    *outputArg2 = 0;

    // Block enclave enter based on current enclave status.
    switch (__oe_enclave_status)
    {
        case OE_OK:
            break;

        case OE_ENCLAVE_ABORTING:
            // Block any ECALL except first time OE_FUNC_DESTRUCTOR call.
            // Don't block ORET here.
            if (code == OE_CODE_ECALL)
            {
                if (func == OE_FUNC_DESTRUCTOR)
                {
                    // Termination function should be only called once.
                    __oe_enclave_status = OE_ENCLAVE_ABORTED;
                }
                else
                {
                    // Return crashing status.
                    *outputArg1 = OE_MakeCallArg1(OE_CODE_ERET, func, 0);
                    *outputArg2 = __oe_enclave_status;
                    return;
                }
            }

            break;

        default:
            // Return crashed status.
            *outputArg1 = OE_MakeCallArg1(OE_CODE_ERET, func, 0);
            *outputArg2 = OE_ENCLAVE_ABORTED;
            return;
    }

    /* Initialize the enclave the first time it is ever entered */
    OE_InitializeEnclave();

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
                /* Eventually calls OE_Exit() and never returns here if
                 * successful */
                _HandleORET(td, func, argIn);
            // fallthrough

            default:
                /* Unexpected case */
                OE_Abort();
        }
    }
    else /* cssa > 0 */
    {
        if ((code == OE_CODE_ECALL) &&
            (func == OE_FUNC_VIRTUAL_EXCEPTION_HANDLER))
        {
            _HandleECall(td, func, argIn, outputArg1, outputArg2);
            return;
        }

        /* ATTN: handle asynchronous exception (AEX) */
        OE_Abort();
    }
}

/*
**==============================================================================
**
** _OE_NotifyNestedExitStart()
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
**     function instead of stack of OE_Enter/__morestack untrusted function.
**     Refer to the _OE_NotifyOCallStart function in host side, and the
**     OCallStartBreakpoint and update_untrusted_ocall_frame function in the
**     python plugin.
**
**==============================================================================
*/
void _OE_NotifyNestedExitStart(uint64_t arg1, OE_OCallContext* ocallContext)
{
    // Check if it is an OCALL.
    OE_Code code = OE_GetCodeFromCallArg1(arg1);
    if (code != OE_CODE_OCALL)
        return;

    // Save the ocallcontext to the callsite of current enclave thread.
    TD* td = TD_Get();
    Callsite* callsite = td->callsites;
    callsite->ocallContext = ocallContext;

    return;
}

void OE_Abort(void)
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
