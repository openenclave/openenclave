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

#include <openenclave/bits/safecrt.h>
#include <openenclave/bits/safemath.h>
#include <openenclave/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/registers.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/utils.h>
#include "asmdefs.h"
#include "enclave.h"
#include "ocalls.h"

/*
**==============================================================================
**
** _set_thread_binding()
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
static oe_once_type _thread_binding_once;
static oe_thread_key _thread_binding_key;
#endif

#if defined(USE_TLS_FOR_THREADING_BINDING)
static void _create_thread_binding_key(void)
{
    oe_thread_key_create(&_thread_binding_key);
}
#endif

static void _set_thread_binding(ThreadBinding* binding)
{
#if defined(USE_TLS_FOR_THREADING_BINDING)
    oe_once(&_thread_binding_once, _create_thread_binding_key);
    oe_thread_setspecific(_thread_binding_key, binding);
#else
    return oe_set_gs_register_base(binding);
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
    oe_once(&_thread_binding_once, _create_thread_binding_key);
    return (ThreadBinding*)oe_thread_getspecific(_thread_binding_key);
#else
    return (ThreadBinding*)oe_get_gs_register_base();
#endif
}

/*
**==============================================================================
**
** _enter_sim()
**
**     Simulated version of oe_enter()
**
**==============================================================================
*/

static oe_result_t _enter_sim(
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
    ThreadBinding* binding = GetThreadBinding();
    td_t* td = NULL;

    /* Reject null parameters */
    if (!enclave || !enclave->addr || !tcs || !tcs->oentry || !tcs->gsbase)
        OE_RAISE(OE_INVALID_PARAMETER);

    tcs->u.entry = (void (*)(void))(enclave->addr + tcs->oentry);

    if (!tcs->u.entry)
        OE_RAISE(OE_NOT_FOUND);

    /* Save old GS and FS register bases */
    binding->host_gs = oe_get_gs_register_base();
    binding->host_fs = oe_get_fs_register_base();

    /* Change GS and FS registers to the values for the enclave thread. At this
     * point thread-locals, pthread, libc etc won't work within the host thread
     * since they depend on FS register.
     * This means that when the enclave makes an ocall, the GS and FS registers
     * must be immediately restored upon entry to host.
     * See __oe_dispatch_ocall.
     */
    td = (td_t*)(enclave->addr + tcs->gsbase);
    oe_set_gs_register_base(td);
    oe_set_fs_register_base((void*)(enclave->addr + tcs->fsbase));

    /* Set td_t.simulate flag */
    td->simulate = true;

    /* Call into enclave */
    if (arg3)
        *arg3 = 0;

    if (arg4)
        *arg4 = 0;

    oe_enter_sim(tcs, aep, arg1, arg2, arg3, arg4, enclave);

    /* Restore GS and GS registers. After this, host side library calls can be
     * safely called.
     */
    oe_set_fs_register_base(binding->host_fs);
    oe_set_gs_register_base(binding->host_gs);

    result = OE_OK;

done:

    return result;
}

/*
**==============================================================================
**
** _do_eenter()
**
**     Execute the EENTER instruction with the given parameters.
**
**==============================================================================
*/

OE_ALWAYS_INLINE
static oe_result_t _do_eenter(
    oe_enclave_t* enclave,
    void* tcs,
    void (*aep)(void),
    oe_code_t code_in,
    uint16_t func_in,
    uint64_t arg_in,
    oe_code_t* code_out,
    uint16_t* func_out,
    uint16_t* result_out,
    uint64_t* arg_out)
{
    oe_result_t result = OE_UNEXPECTED;

    if (code_out)
        *code_out = OE_CODE_NONE;

    if (func_out)
        *func_out = 0;

    if (result_out)
        *func_out = 0;

    if (arg_out)
        *arg_out = 0;

    if (!code_out || !func_out || !result_out || !arg_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_TRACE_VERBOSE(
        "_do_eenter(tcs=%p aep=%p codeIn=%d, funcIn=%x argIn=%llx)\n",
        tcs,
        aep,
        code_in,
        func_in,
        OE_LLX(arg_in));

    /* Call oe_enter() assembly function (enter.S) */
    {
        uint64_t arg1 = oe_make_call_arg1(code_in, func_in, 0, OE_OK);
        uint64_t arg2 = (uint64_t)arg_in;
        uint64_t arg3 = 0;
        uint64_t arg4 = 0;

        if (enclave->simulate)
        {
            OE_CHECK(_enter_sim(enclave, tcs, aep, arg1, arg2, &arg3, &arg4));
        }
        else
        {
            oe_enter(tcs, aep, arg1, arg2, &arg3, &arg4, enclave);
        }

        *code_out = oe_get_code_from_call_arg1(arg3);
        *func_out = oe_get_func_from_call_arg1(arg3);
        *result_out = oe_get_result_from_call_arg1(arg3);
        *arg_out = arg4;
    }

    result = OE_OK;

done:
    return result;
}

/*
**==============================================================================
**
** _find_host_func()
**
**     Find the function in the host with the given name.
**
**==============================================================================
*/

static oe_host_func_t _find_host_func(const char* name)
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
** _handle_call_host()
**
**     Handle calls from the enclave
**
**==============================================================================
*/

static void _handle_call_host(uint64_t arg, oe_enclave_t* enclave)
{
    oe_call_host_args_t* args = (oe_call_host_args_t*)arg;
    oe_host_func_t func;

    if (!args)
        return;

    args->result = OE_UNEXPECTED;

    /* Find the host function with this name */
    if (!(func = _find_host_func(args->func)))
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
** _handle_call_host_function()
**
** Handle calls from the enclave.
**
**==============================================================================
*/

static oe_result_t _handle_call_host_function(
    uint64_t arg,
    oe_enclave_t* enclave)
{
    oe_call_host_function_args_t* args_ptr = NULL;
    oe_result_t result = OE_OK;
    oe_ocall_func_t func = NULL;
    size_t buffer_size = 0;

    args_ptr = (oe_call_host_function_args_t*)arg;
    if (args_ptr == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Input and output buffers must not be NULL.
    if (args_ptr->input_buffer == NULL || args_ptr->output_buffer == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Fetch matching function.
    if (args_ptr->function_id >= enclave->num_ocalls)
        OE_RAISE(OE_NOT_FOUND);

    func = enclave->ocalls[args_ptr->function_id];
    if (func == NULL)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    OE_CHECK(
        oe_safe_add_u64(
            args_ptr->input_buffer_size,
            args_ptr->output_buffer_size,
            &buffer_size));

    // Buffer sizes must be pointer aligned.
    if ((args_ptr->input_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if ((args_ptr->output_buffer_size % OE_EDGER8R_BUFFER_ALIGNMENT) != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Call the function.
    func(
        args_ptr->input_buffer,
        args_ptr->input_buffer_size,
        args_ptr->output_buffer,
        args_ptr->output_buffer_size,
        &args_ptr->output_bytes_written);

    // The ocall succeeded.
    args_ptr->result = OE_OK;
    result = OE_OK;
done:

    return result;
}

/*
**==============================================================================
**
** _handle_ocall()
**
**     Handle calls from the enclave (OCALL)
**
**==============================================================================
*/

static oe_result_t _handle_ocall(
    oe_enclave_t* enclave,
    void* tcs,
    uint16_t func,
    uint64_t arg_in,
    uint64_t* arg_out)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!enclave || !tcs)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (arg_out)
        *arg_out = 0;

    switch ((oe_func_t)func)
    {
        case OE_OCALL_CALL_HOST:
            _handle_call_host(arg_in, enclave);
            break;

        case OE_OCALL_CALL_HOST_BY_ADDRESS:
            _handle_call_host_by_address(arg_in, enclave);
            break;

        case OE_OCALL_CALL_HOST_FUNCTION:
            _handle_call_host_function(arg_in, enclave);
            break;

        case OE_OCALL_MALLOC:
            HandleMalloc(arg_in, arg_out);
            break;

        case OE_OCALL_REALLOC:
            HandleRealloc(arg_in, arg_out);
            break;

        case OE_OCALL_FREE:
            HandleFree(arg_in);
            break;

        case OE_OCALL_WRITE:
            HandlePrint(arg_in);
            break;

        case OE_OCALL_THREAD_WAIT:
            HandleThreadWait(enclave, arg_in);
            break;

        case OE_OCALL_THREAD_WAKE:
            HandleThreadWake(enclave, arg_in);
            break;

        case OE_OCALL_THREAD_WAKE_WAIT:
            HandleThreadWakeWait(enclave, arg_in);
            break;

        case OE_OCALL_GET_QUOTE:
            HandleGetQuote(arg_in);
            break;

#ifdef OE_USE_LIBSGX
        // Quote revocation is supported only on libsgx platforms.
        case OE_OCALL_GET_REVOCATION_INFO:
            HandleGetQuoteRevocationInfo(arg_in);
            break;
        case OE_OCALL_GET_QE_ID_INFO:
            HandleGetQuoteEnclaveIdentityInfo(arg_in);
            break;
#endif

        case OE_OCALL_GET_QE_TARGET_INFO:
            HandleGetQETargetInfo(arg_in);
            break;

        case OE_OCALL_SLEEP:
            oe_handle_sleep(arg_in);
            break;

        case OE_OCALL_GET_TIME:
            oe_handle_get_time(arg_in, arg_out);
            break;

        case OE_OCALL_BACKTRACE_SYMBOLS:
            oe_handle_backtrace_symbols(enclave, arg_in);
            break;

        case OE_OCALL_LOG:
            oe_handle_log(enclave, arg_in);
            break;

        default:
        {
            /* No function found with the number */
            OE_RAISE(OE_NOT_FOUND);
        }
    }

    result = OE_OK;

done:

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
**     arg1_out - first argument to pass to EENTER (code + func)
**     arg2_out - second argument to pass to EENTER (ORET argument)
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
    uint64_t* arg1_out,
    uint64_t* arg2_out,
    void* tcs_,
    oe_enclave_t* enclave)
{
    const oe_code_t code = oe_get_code_from_call_arg1(arg1);
    const uint16_t func = oe_get_func_from_call_arg1(arg1);
    const uint64_t arg = arg2;
    sgx_tcs_t* tcs = (sgx_tcs_t*)tcs_;

    if (code == OE_CODE_OCALL)
    {
        // Get the current thread-binding.
        // Handling an OCALL can make ecalls to other enclaves, which
        // may result in overriding the thread-binding. Therefore,
        // upon return from the OCALL, the binding must be restored.
        ThreadBinding* binding = NULL;
        uint64_t arg_out = 0;

        if (enclave->simulate)
        {
            /**
             * GetThreadBinding may not work since it uses pthread APIs.
             * pthread depends on FS register being set correctly, which
             * is what we are trying to do. So loop through the bindings
             * to figure out the correct one for the given tcs.
             */
            for (size_t i = 0; i < OE_COUNTOF(enclave->bindings); ++i)
            {
                if (enclave->bindings[i].tcs == (uint64_t)tcs)
                {
                    binding = &enclave->bindings[i];
                    break;
                }
            }

            /**
             * Restore FS and GS registers when making an OCALL.
             * This makes sure that thread-locals, libc on host work.
             */
            oe_set_fs_register_base(binding->host_fs);
            oe_set_gs_register_base(binding->host_gs);
        }
        else
        {
            // FS, GS registers are restored by the EEXIT instruction.
            binding = GetThreadBinding();
        }

        oe_result_t result = _handle_ocall(enclave, tcs, func, arg, &arg_out);
        *arg1_out = oe_make_call_arg1(OE_CODE_ORET, func, 0, result);
        *arg2_out = arg_out;

        // Restore the binding.
        _set_thread_binding(binding);

        if (enclave->simulate)
        {
            // Prior to returning back to the enclave, set the GS and FS
            // registers to their values for the enclave thread.
            oe_set_fs_register_base((void*)(enclave->addr + tcs->fsbase));
            oe_set_gs_register_base((void*)(enclave->addr + tcs->gsbase));
        }
        return 0;
    }

    /* Not an OCALL */
    return 1;
}

/*
**==============================================================================
**
** _assign_tcs()
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

static void* _assign_tcs(oe_enclave_t* enclave)
{
    void* tcs = NULL;
    size_t i;
    oe_thread thread = oe_thread_self();

    oe_mutex_lock(&enclave->lock);
    {
        /* First attempt to find a busy td_t owned by this thread */
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
                    _set_thread_binding(binding);
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
** _release_tcs()
**
**     Decrement the ThreadBinding.count field of the binding associated with
**     the given TCS. If the field becomes zero, the binding is dissolved.
**
**==============================================================================
*/

static void _release_tcs(oe_enclave_t* enclave, void* tcs)
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
                    _set_thread_binding(NULL);
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
    uint64_t* arg_out_ptr)
{
    oe_result_t result = OE_UNEXPECTED;
    void* tcs = NULL;
    oe_code_t code = OE_CODE_ECALL;
    oe_code_t code_out = 0;
    uint16_t func_out = 0;
    uint16_t result_out = 0;
    uint64_t arg_out = 0;

    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Assign a td_t for this operation */
    if (!(tcs = _assign_tcs(enclave)))
        OE_RAISE(OE_OUT_OF_THREADS);

    /* Perform ECALL or ORET */
    OE_CHECK(
        _do_eenter(
            enclave,
            tcs,
            OE_AEP,
            code,
            func,
            arg,
            &code_out,
            &func_out,
            &result_out,
            &arg_out));

    /* Process OCALLS */
    if (code_out != OE_CODE_ERET)
        OE_RAISE(OE_UNEXPECTED);

    if (arg_out_ptr)
        *arg_out_ptr = arg_out;

    result = (oe_result_t)result_out;

done:

    if (enclave && tcs)
        _release_tcs(enclave, tcs);

    /* ATTN: this causes an assertion with call nesting. */
    /* ATTN: make enclave argument a cookie. */
    /* ATTN: the SetEnclave() function no longer exists */
    /* SetEnclave(NULL); */

    return result;
}

/*
**==============================================================================
**
** _find_enclave_func()
**
**     Find the enclave function with the given name
**
**==============================================================================
*/

static uint64_t _find_enclave_func(
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
    oe_call_enclave_args_t call_enclave_args;

    /* Reject invalid parameters */
    if (!enclave || !func)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the call_enclave_args structure */
    {
        if (!(call_enclave_args.vaddr =
                  _find_enclave_func(enclave, func, &call_enclave_args.func)))
        {
            OE_RAISE(OE_NOT_FOUND);
        }

        call_enclave_args.args = args;
        call_enclave_args.result = OE_UNEXPECTED;
    }

    /* Perform the ECALL */
    {
        uint64_t arg_out = 0;

        OE_CHECK(
            oe_ecall(
                enclave,
                OE_ECALL_CALL_ENCLAVE,
                (uint64_t)&call_enclave_args,
                &arg_out));

        OE_CHECK((oe_result_t)arg_out);
    }

    /* Check the result */
    OE_CHECK(call_enclave_args.result);

    result = OE_OK;

done:
    return result;
}

/*
**==============================================================================
**
** oe_call_enclave_function()
**
** Call the enclave function specified by the given function-id.
** Note: Currently only SGX style marshaling is supported. input_buffer contains
** the marshaling args structure.
**
**==============================================================================
*/

oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_enclave_function_args_t args;

    /* Reject invalid parameters */
    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the call_enclave_args structure */
    {
        args.function_id = function_id;
        args.input_buffer = input_buffer;
        args.input_buffer_size = input_buffer_size;
        args.output_buffer = output_buffer;
        args.output_buffer_size = output_buffer_size;
        args.output_bytes_written = 0;
        args.result = OE_UNEXPECTED;
    }

    /* Perform the ECALL */
    {
        uint64_t arg_out = 0;

        OE_CHECK(
            oe_ecall(
                enclave,
                OE_ECALL_CALL_ENCLAVE_FUNCTION,
                (uint64_t)&args,
                &arg_out));
        OE_CHECK((oe_result_t)arg_out);
    }

    /* Check the result */
    OE_CHECK(args.result);

    *output_bytes_written = args.output_bytes_written;
    result = OE_OK;

done:
    return result;
}

/*
** These two functions are needed to notify the debugger. They should not be
** optimized out even though they don't do anything in here.
*/

OE_NO_OPTIMIZE_BEGIN

OE_NEVER_INLINE void oe_notify_ocall_start(
    oe_host_ocall_frame_t* frame_pointer,
    void* tcs)
{
    OE_UNUSED(frame_pointer);
    OE_UNUSED(tcs);

    return;
}

OE_NEVER_INLINE void oe_notify_ocall_end(
    oe_host_ocall_frame_t* frame_pointer,
    void* tcs)
{
    OE_UNUSED(frame_pointer);
    OE_UNUSED(tcs);

    return;
}

OE_NO_OPTIMIZE_END
