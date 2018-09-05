// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <stdio.h>
#include <string.h>

#if defined(__linux__)
#include <dlfcn.h>
#include <linux/futex.h>
#include <setjmp.h>
#include <sys/mman.h>
#include <sys/syscall.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#else
#error "unsupported platform"
#endif

#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/registers.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/trace.h>
#include <openenclave/internal/utils.h>
#include "asmdefs.h"
#include "enclave.h"
#include "ocalls.h"

/*
**==============================================================================
**
** _SetThreadBinding()
**
**     Store the thread data in the GS segment register. Note that the GS
**     register is unused on X86-64 on Linux, unlike the FS register that is
**     used by the pthread implementation.
**
**     The OE_AEP() function (aep.S) uses the GS segment register to retrieve
**     the ThreadBinding.tcs field.
**
**==============================================================================
*/

#define USE_TLS_FOR_THREADING_BINDING

#if defined(USE_TLS_FOR_THREADING_BINDING)
static oe_once_type _threadBindingOnce;
static oe_thread_key _threadBindingKey;
#endif

#if defined(USE_TLS_FOR_THREADING_BINDING)
static void _CreateThreadBindingKey(void)
{
    oe_thread_key_create(&_threadBindingKey);
}
#endif

static void _SetThreadBinding(ThreadBinding* binding)
{
#if defined(USE_TLS_FOR_THREADING_BINDING)
    oe_once(&_threadBindingOnce, _CreateThreadBindingKey);
    oe_thread_setspecific(_threadBindingKey, binding);
#else
    return (ThreadBinding*)oe_get_gs_register_base();
#endif
}

/*
**==============================================================================
**
** GetThreadBinding()
**
**     Retrieve the a pointer to the ThreadBinding from the GS segment register.
**
**==============================================================================
*/

ThreadBinding* GetThreadBinding()
{
#if defined(USE_TLS_FOR_THREADING_BINDING)
    oe_once(&_threadBindingOnce, _CreateThreadBindingKey);
    return (ThreadBinding*)oe_thread_getspecific(_threadBindingKey);
#else
    return (ThreadBinding*)oe_get_gs_register_base();
#endif
}

/*
**==============================================================================
**
** _EnterSim()
**
**     Simulated version of oe_enter()
**
**==============================================================================
*/

static oe_result_t _EnterSim(
    oe_enclave_t* enclave,
    void* tcs_,
    void (*aep)(void),
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_tcs_t* tcs = (sgx_tcs_t*)tcs_;
    const void* saved_gsbase = NULL;

    /* Reject null parameters */
    if (!enclave || !enclave->addr || !tcs || !tcs->oentry || !tcs->gsbase)
        OE_THROW(OE_INVALID_PARAMETER);

    tcs->u.entry = (void (*)(void))(enclave->addr + tcs->oentry);

    if (!tcs->u.entry)
        OE_THROW(OE_NOT_FOUND);

    /* Save old GS register base, and set new one */
    const void* gsbase;
    {
        gsbase = (void*)(enclave->addr + tcs->gsbase);
        saved_gsbase = oe_get_gs_register_base();

        /* Set TD.simulate flag */
        {
            TD* td = (TD*)gsbase;
            td->simulate = true;
        }
    }

    /* Call into enclave */
    {
        if (arg3)
            *arg3 = 0;

        if (arg4)
            *arg4 = 0;

        oe_set_gs_register_base(gsbase);
        oe_enter_sim(tcs, aep, arg1, arg2, arg3, arg4, enclave);
        oe_set_gs_register_base(saved_gsbase);
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

/*
**==============================================================================
**
** _DoEENTER()
**
**     Execute the EENTER instruction with the given parameters.
**
**==============================================================================
*/

OE_ALWAYS_INLINE
static oe_result_t _DoEENTER(
    oe_enclave_t* enclave,
    void* tcs,
    void (*aep)(void),
    oe_code_t codeIn,
    uint16_t funcIn,
    uint64_t argIn,
    oe_code_t* codeOut,
    uint16_t* funcOut,
    uint16_t* resultOut,
    uint64_t* argOut)
{
    oe_result_t result = OE_UNEXPECTED;

    if (codeOut)
        *codeOut = OE_CODE_NONE;

    if (funcOut)
        *funcOut = 0;

    if (resultOut)
        *funcOut = 0;

    if (argOut)
        *argOut = 0;

    if (!codeOut || !funcOut || !resultOut || !argOut)
        OE_THROW(OE_INVALID_PARAMETER);

    OE_TRACE_INFO(
        "_DoEENTER(tcs=%p aep=%p codeIn=%d, funcIn=%x argIn=%llx)\n",
        tcs,
        aep,
        codeIn,
        funcIn,
        OE_LLX(argIn));

    /* Call oe_enter() assembly function (enter.S) */
    {
        uint64_t arg1 = oe_make_call_arg1(codeIn, funcIn, 0, OE_OK);
        uint64_t arg2 = (uint64_t)argIn;
        uint64_t arg3 = 0;
        uint64_t arg4 = 0;

        if (enclave->simulate)
        {
            OE_TRY(_EnterSim(enclave, tcs, aep, arg1, arg2, &arg3, &arg4));
        }
        else
        {
            oe_enter(tcs, aep, arg1, arg2, &arg3, &arg4, enclave);
        }

        *codeOut = oe_get_code_from_call_arg1(arg3);
        *funcOut = oe_get_func_from_call_arg1(arg3);
        *resultOut = oe_get_result_from_call_arg1(arg3);
        *argOut = arg4;
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

/*
**==============================================================================
**
** _FindHostFunc()
**
**     Find the function in the host with the given name.
**
**==============================================================================
*/

static oe_host_func_t _FindHostFunc(const char* name)
{
#if defined(__linux__)

    void* handle = dlopen(NULL, RTLD_NOW | RTLD_GLOBAL);
    if (!handle)
        return NULL;

    oe_host_func_t func = (oe_host_func_t)dlsym(handle, name);
    dlclose(handle);

    return func;

#elif defined(_WIN32)

    HANDLE handle = GetModuleHandle(NULL);

    if (!handle)
        return NULL;

    return (oe_host_func_t)GetProcAddress(handle, name);

#endif
}

/*
**==============================================================================
**
** _HandleCallHost()
**
**     Handle calls from the enclave
**
**==============================================================================
*/

static void _HandleCallHost(uint64_t arg, oe_enclave_t* enclave)
{
    oe_call_host_args_t* args = (oe_call_host_args_t*)arg;
    oe_host_func_t func;

    if (!args)
        return;

    args->result = OE_UNEXPECTED;

    /* Find the host function with this name */
    if (!(func = _FindHostFunc(args->func)))
    {
        args->result = OE_NOT_FOUND;
        return;
    }

    /* Invoke the function */
    func(args->args, enclave);

    args->result = OE_OK;
}

/*
**==============================================================================
**
** _handle_call_host_by_address()
**
**     Handle calls from the enclave
**
**==============================================================================
*/

static void _handle_call_host_by_address(uint64_t arg, oe_enclave_t* enclave)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_host_by_address_args_t* args = (oe_call_host_by_address_args_t*)arg;

    if (!args || !args->func)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Invoke the function */
    args->func(args->args, enclave);

    result = OE_OK;

done:

    if (args)
        args->result = result;
}

/*
**==============================================================================
**
** _HandleOCALL()
**
**     Handle calls from the enclave (OCALL)
**
**==============================================================================
*/

static oe_result_t _HandleOCALL(
    oe_enclave_t* enclave,
    void* tcs,
    uint16_t func,
    uint64_t argIn,
    uint64_t* argOut)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!enclave || !tcs)
        OE_THROW(OE_INVALID_PARAMETER);

    if (argOut)
        *argOut = 0;

    switch ((oe_func_t)func)
    {
        case OE_OCALL_CALL_HOST:
            _HandleCallHost(argIn, enclave);
            break;

        case OE_OCALL_CALL_HOST_BY_ADDRESS:
            _handle_call_host_by_address(argIn, enclave);
            break;

        case OE_OCALL_MALLOC:
            HandleMalloc(argIn, argOut);
            break;

        case OE_OCALL_REALLOC:
            HandleRealloc(argIn, argOut);
            break;

        case OE_OCALL_FREE:
            HandleFree(argIn);
            break;

        case OE_OCALL_PUTS:
            HandlePuts(argIn);
            break;

        case OE_OCALL_PRINT:
            HandlePrint(argIn);
            break;

        case OE_OCALL_PUTCHAR:
            HandlePutchar(argIn);
            break;

        case OE_OCALL_THREAD_WAIT:
            HandleThreadWait(enclave, argIn);
            break;

        case OE_OCALL_THREAD_WAKE:
            HandleThreadWake(enclave, argIn);
            break;

        case OE_OCALL_THREAD_WAKE_WAIT:
            HandleThreadWakeWait(enclave, argIn);
            break;

        case OE_OCALL_GET_QUOTE:
            HandleGetQuote(argIn);
            break;

#ifdef OE_USE_LIBSGX
        // Quote revocation is supported only on libsgx platforms.
        case OE_OCALL_GET_REVOCATION_INFO:
            HandleGetQuoteRevocationInfo(argIn);
            break;
#endif

        case OE_OCALL_GET_QE_TARGET_INFO:
            HandleGetQETargetInfo(argIn);
            break;

        case OE_OCALL_SLEEP:
            oe_handle_sleep(argIn);
            break;

        case OE_OCALL_GET_TIME:
            oe_handle_get_time(argIn, argOut);
            break;

        case OE_OCALL_BACKTRACE_SYMBOLS:
            oe_handle_backtrace_symbols(enclave, argIn);
            break;

        default:
        {
            /* No function found with the number */
            OE_THROW(OE_NOT_FOUND);
        }
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

/*
**==============================================================================
**
** __oe_dispatch_ocall()
**
**     This function is called by oe_enter() (see enter.S). It checks to
**     to see if EENTER returned in order to perform an OCALL. If so it
**     dispatches the OCALL.
**
** Parameters:
**     arg1 - first argument from EENTER return (code + func)
**     arg2 - second argument from EENTER return (OCALL argument)
**     arg1Out - first argument to pass to EENTER (code + func)
**     arg2Out - second argument to pass to EENTER (ORET argument)
**
** Returns:
**     0 - An OCALL was dispatched
**     1 - No OCALL was dispatched
**
**==============================================================================
*/

int __oe_dispatch_ocall(
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg1Out,
    uint64_t* arg2Out,
    void* tcs,
    oe_enclave_t* enclave)
{
    const oe_code_t code = oe_get_code_from_call_arg1(arg1);
    const uint16_t func = oe_get_func_from_call_arg1(arg1);
    const uint64_t arg = arg2;

    if (code == OE_CODE_OCALL)
    {
        uint64_t argOut = 0;

        oe_result_t result = _HandleOCALL(enclave, tcs, func, arg, &argOut);
        *arg1Out = oe_make_call_arg1(OE_CODE_ORET, func, 0, result);
        *arg2Out = argOut;

        return 0;
    }

    /* Not an OCALL */
    return 1;
}

/*
**==============================================================================
**
** _AssignTCS()
**
**     This function establishes a binding between:
**         - the calling host thread
**         - an enclave thread context
**
**     If such a binding already exists, the binding's count in incremented.
**     Else, the calling host thread is bound to the first available enclave
**     thread context.
**
**     Returns the address of the thread control structure (TCS) corresponding
**     to the enclave thread context.
**
**==============================================================================
*/

static void* _AssignTCS(oe_enclave_t* enclave)
{
    void* tcs = NULL;
    size_t i;
    oe_thread thread = oe_thread_self();

    oe_mutex_lock(&enclave->lock);
    {
        /* First attempt to find a busy TD owned by this thread */
        for (i = 0; i < enclave->num_bindings; i++)
        {
            ThreadBinding* binding = &enclave->bindings[i];

            if ((binding->flags & _OE_THREAD_BUSY) && binding->thread == thread)
            {
                binding->count++;
                tcs = (void*)binding->tcs;
                break;
            }
        }

        /* If binding not found above, look for an available ThreadBinding */
        if (!tcs)
        {
            for (i = 0; i < enclave->num_bindings; i++)
            {
                ThreadBinding* binding = &enclave->bindings[i];

                if (!(binding->flags & _OE_THREAD_BUSY))
                {
                    binding->flags |= _OE_THREAD_BUSY;
                    binding->thread = thread;
                    binding->count = 1;
                    tcs = (void*)binding->tcs;

                    /* Set into TSD so asynchronous exceptions can get it */
                    _SetThreadBinding(binding);
                    assert(GetThreadBinding() == binding);
                    break;
                }
            }
        }
    }
    oe_mutex_unlock(&enclave->lock);

    return tcs;
}

/*
**==============================================================================
**
** _ReleaseTCS()
**
**     Decrement the ThreadBinding.count field of the binding associated with
**     the given TCS. If the field becomes zero, the binding is dissolved.
**
**==============================================================================
*/

static void _ReleaseTCS(oe_enclave_t* enclave, void* tcs)
{
    size_t i;

    oe_mutex_lock(&enclave->lock);
    {
        for (i = 0; i < enclave->num_bindings; i++)
        {
            ThreadBinding* binding = &enclave->bindings[i];

            if ((binding->flags & _OE_THREAD_BUSY) &&
                (void*)binding->tcs == tcs)
            {
                binding->count--;

                if (binding->count == 0)
                {
                    binding->flags &= (~_OE_THREAD_BUSY);
                    binding->thread = 0;
                    memset(&binding->event, 0, sizeof(binding->event));
                    _SetThreadBinding(NULL);
                    assert(GetThreadBinding() == NULL);
                }
                break;
            }
        }
    }
    oe_mutex_unlock(&enclave->lock);
}

/*
**==============================================================================
**
** oe_ecall()
**
**     This function initiates an ECALL.
**
**==============================================================================
*/

oe_result_t oe_ecall(
    oe_enclave_t* enclave,
    uint16_t func,
    uint64_t arg,
    uint64_t* argOutPtr)
{
    oe_result_t result = OE_UNEXPECTED;
    void* tcs = NULL;
    oe_code_t code = OE_CODE_ECALL;
    oe_code_t codeOut = 0;
    uint16_t funcOut = 0;
    uint16_t resultOut = 0;
    uint64_t argOut = 0;

    if (!enclave)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Assign a TD for this operation */
    if (!(tcs = _AssignTCS(enclave)))
        OE_THROW(OE_OUT_OF_THREADS);

    /* Perform ECALL or ORET */
    OE_TRY(
        _DoEENTER(
            enclave,
            tcs,
            OE_AEP,
            code,
            func,
            arg,
            &codeOut,
            &funcOut,
            &resultOut,
            &argOut));

    /* Process OCALLS */
    if (codeOut != OE_CODE_ERET)
        OE_THROW(OE_UNEXPECTED);

    if (argOutPtr)
        *argOutPtr = argOut;

    result = (oe_result_t)resultOut;

OE_CATCH:

    if (enclave && tcs)
        _ReleaseTCS(enclave, tcs);

    /* ATTN: this causes an assertion with call nesting. */
    /* ATTN: make enclave argument a cookie. */
    /* ATTN: the SetEnclave() function no longer exists */
    /* SetEnclave(NULL); */

    return result;
}

/*
**==============================================================================
**
** _FindEnclaveFunc()
**
**     Find the enclave function with the given name
**
**==============================================================================
*/

static uint64_t _FindEnclaveFunc(
    oe_enclave_t* enclave,
    const char* func,
    uint64_t* index)
{
    size_t i;

    if (index)
        *index = 0;

    /* Reject null parameters and empty string funcs (checked by !*func). */
    if (!enclave || !func || !*func || !index)
        return 0;

    size_t len = strlen(func);
    uint64_t code = StrCode(func, len);

    for (i = 0; i < enclave->num_ecalls; i++)
    {
        const ECallNameAddr* p = &enclave->ecalls[i];

        if (p->code == code && memcmp(p->name, func, len) == 0)
        {
            *index = i;
            return enclave->ecalls[i].vaddr;
        }
    }

    /* Not found! */
    return 0;
}

/*
**==============================================================================
**
** oe_call_enclave()
**
**     Call the named function in the enclave.
**
**==============================================================================
*/

oe_result_t oe_call_enclave(oe_enclave_t* enclave, const char* func, void* args)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_enclave_args_t callEnclaveArgs;

    /* Reject invalid parameters */
    if (!enclave || !func)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize the callEnclaveArgs structure */
    {
        if (!(callEnclaveArgs.vaddr =
                  _FindEnclaveFunc(enclave, func, &callEnclaveArgs.func)))
        {
            OE_THROW(OE_NOT_FOUND);
        }

        callEnclaveArgs.args = args;
        callEnclaveArgs.result = OE_UNEXPECTED;
    }

    /* Perform the ECALL */
    {
        uint64_t argOut = 0;

        OE_TRY(
            oe_ecall(
                enclave,
                OE_ECALL_CALL_ENCLAVE,
                (uint64_t)&callEnclaveArgs,
                &argOut));
        OE_TRY(argOut);
    }

    /* Check the result */
    OE_TRY(callEnclaveArgs.result);

    result = OE_OK;

OE_CATCH:
    return result;
}

/*
** These two functions are needed to notify the debugger. They should not be
** optimized out even though they don't do anything in here.
*/

OE_NO_OPTIMIZE_BEGIN

OE_NEVER_INLINE void _oe_notify_ocall_start(
    oe_host_ocall_frame_t* frame_pointer,
    void* tcs)
{
    OE_UNUSED(frame_pointer);
    OE_UNUSED(tcs);

    return;
}

OE_NEVER_INLINE void _oe_notify_ocall_end(
    oe_host_ocall_frame_t* frame_pointer,
    void* tcs)
{
    OE_UNUSED(frame_pointer);
    OE_UNUSED(tcs);

    return;
}

OE_NO_OPTIMIZE_END
