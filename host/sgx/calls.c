// Copyright (c) Open Enclave SDK contributors.
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
#include <openenclave/internal/debugrt/host.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/registers.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/safemath.h>
#include <openenclave/internal/sgxtypes.h>
#include <openenclave/internal/switchless.h>
#include <openenclave/internal/utils.h>
#include "../calls.h"
#include "../hostthread.h"
#include "../ocalls.h"
#include "asmdefs.h"
#include "enclave.h"
#include "ocalls.h"

/*
**==============================================================================
**
** _set_thread_binding()
**
**     Store the enclave/tcs binding for the current thread in thread specific
**     storage.
**
**==============================================================================
*/

static oe_once_type _thread_binding_once;
static oe_thread_key _thread_binding_key;

static void _create_thread_binding_key(void)
{
    oe_thread_key_create(&_thread_binding_key);
}

static void _set_thread_binding(oe_thread_binding_t* binding)
{
    oe_once(&_thread_binding_once, _create_thread_binding_key);
    oe_thread_setspecific(_thread_binding_key, binding);
}

/*
**==============================================================================
**
** oe_get_thread_binding()
**
**     Retrieve the a pointer to the oe_get_thread_binding from thread specific
**     storage.
**
**==============================================================================
*/

oe_thread_binding_t* oe_get_thread_binding()
{
    oe_once(&_thread_binding_once, _create_thread_binding_key);
    return (oe_thread_binding_t*)oe_thread_getspecific(_thread_binding_key);
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
    uint64_t aep,
    uint64_t arg1,
    uint64_t arg2,
    uint64_t* arg3,
    uint64_t* arg4)
{
    oe_result_t result = OE_UNEXPECTED;
    sgx_tcs_t* tcs = (sgx_tcs_t*)tcs_;
    td_t* td = NULL;

    /* Reject null parameters */
    if (!enclave || !enclave->addr || !tcs || !tcs->oentry || !tcs->gsbase)
        OE_RAISE(OE_INVALID_PARAMETER);

    tcs->u.entry = (void (*)(void))(enclave->addr + tcs->oentry);

    if (!tcs->u.entry)
        OE_RAISE(OE_NOT_FOUND);

    /* Set td_t.simulate flag */
    td = (td_t*)(enclave->addr + tcs->gsbase);
    td->simulate = true;

    /* Call into enclave */
    if (arg3)
        *arg3 = 0;

    if (arg4)
        *arg4 = 0;

    oe_enter_sim(tcs, aep, arg1, arg2, arg3, arg4, enclave);
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
    uint64_t aep,
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
        *result_out = 0;

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
** oe_handle_call_host_function()
**
** Handle calls from the enclave.
**
**==============================================================================
*/

oe_result_t oe_handle_call_host_function(uint64_t arg, oe_enclave_t* enclave)
{
    oe_call_host_function_args_t* args_ptr = NULL;
    oe_result_t result = OE_OK;
    oe_ocall_func_t func = NULL;
    size_t buffer_size = 0;
    ocall_table_t ocall_table;

    args_ptr = (oe_call_host_function_args_t*)arg;
    if (args_ptr == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Input and output buffers must not be NULL.
    if (args_ptr->input_buffer == NULL || args_ptr->output_buffer == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Resolve which ocall table to use.
    if (args_ptr->table_id == OE_UINT64_MAX)
    {
        ocall_table.ocalls = enclave->ocalls;
        ocall_table.num_ocalls = enclave->num_ocalls;
    }
    else
    {
        if (args_ptr->table_id >= OE_MAX_OCALL_TABLES)
            OE_RAISE(OE_NOT_FOUND);

        ocall_table.ocalls = _ocall_tables[args_ptr->table_id].ocalls;
        ocall_table.num_ocalls = _ocall_tables[args_ptr->table_id].num_ocalls;

        if (!ocall_table.ocalls)
            OE_RAISE(OE_NOT_FOUND);
    }

    // Fetch matching function.
    if (args_ptr->function_id >= ocall_table.num_ocalls)
        OE_RAISE(OE_NOT_FOUND);

    func = ocall_table.ocalls[args_ptr->function_id];
    if (func == NULL)
    {
        result = OE_NOT_FOUND;
        goto done;
    }

    OE_CHECK(oe_safe_add_u64(
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
    OE_ATOMIC_MEMORY_BARRIER_RELEASE();
    args_ptr->result = OE_OK;
    result = OE_OK;
done:

    return result;
}

static const char* oe_ocall_str(oe_func_t ocall)
{
    // clang-format off
    static const char* func_names[] =
    {
        "CALL_HOST_FUNCTION",
        "THREAD_WAKE",
        "THREAD_WAIT",
        "MALLOC",
        "FREE",
        "GET_TIME"
    };
    // clang-format on

    OE_STATIC_ASSERT(OE_OCALL_BASE + OE_COUNTOF(func_names) == OE_OCALL_MAX);

    if (ocall >= OE_OCALL_BASE && ocall < OE_OCALL_MAX)
        return func_names[ocall - OE_OCALL_BASE];
    else
        return "UNKNOWN";
};

static const char* oe_ecall_str(oe_func_t ecall)
{
    // clang-format off
    static const char* func_names[] =
    {
        "DESTRUCTOR",
        "INIT_ENCLAVE",
        "CALL_ENCLAVE_FUNCTION",
        "VIRTUAL_EXCEPTION_HANDLER"
    };
    // clang-format on

    OE_STATIC_ASSERT(OE_ECALL_BASE + OE_COUNTOF(func_names) == OE_ECALL_MAX);

    if (ecall >= OE_ECALL_BASE && ecall < OE_ECALL_MAX)
        return func_names[ecall - OE_ECALL_BASE];
    else
        return "UNKNOWN";
};

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

    oe_log(
        OE_LOG_LEVEL_VERBOSE,
        "%s 0x%x %s: %s\n",
        enclave->path,
        enclave->addr,
        func == OE_OCALL_CALL_HOST_FUNCTION ? "EDL_OCALL" : "OE_OCALL",
        oe_ocall_str(func));

    switch ((oe_func_t)func)
    {
        case OE_OCALL_CALL_HOST_FUNCTION:
            OE_CHECK(oe_handle_call_host_function(arg_in, enclave));
            break;

        case OE_OCALL_MALLOC:
            HandleMalloc(arg_in, arg_out);
            break;

        case OE_OCALL_FREE:
            HandleFree(arg_in);
            break;

        case OE_OCALL_THREAD_WAIT:
            HandleThreadWait(enclave, arg_in);
            break;

        case OE_OCALL_THREAD_WAKE:
            HandleThreadWake(enclave, arg_in);
            break;

        case OE_OCALL_GET_TIME:
            oe_handle_get_time(arg_in, arg_out);
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
        oe_thread_binding_t* binding = oe_get_thread_binding();
        uint64_t arg_out = 0;

        oe_result_t result = _handle_ocall(enclave, tcs, func, arg, &arg_out);
        *arg1_out = oe_make_call_arg1(OE_CODE_ORET, func, 0, result);
        *arg2_out = arg_out;

        // Restore the binding.
        _set_thread_binding(binding);
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
    oe_thread_t thread = oe_thread_self();

    oe_mutex_lock(&enclave->lock);
    {
        /* First attempt to find a busy td_t owned by this thread */
        for (i = 0; i < enclave->num_bindings; i++)
        {
            oe_thread_binding_t* binding = &enclave->bindings[i];

            if ((binding->flags & _OE_THREAD_BUSY) && binding->thread == thread)
            {
                binding->count++;
                tcs = (void*)binding->tcs;

                /* Notify the debugger runtime */
                if (enclave->debug && enclave->debug_enclave != NULL)
                    oe_debug_push_thread_binding(
                        enclave->debug_enclave, (sgx_tcs_t*)tcs);
                break;
            }
        }

        /* If binding not found above, look for an available ThreadBinding */
        if (!tcs)
        {
            for (i = 0; i < enclave->num_bindings; i++)
            {
                oe_thread_binding_t* binding = &enclave->bindings[i];

                if (!(binding->flags & _OE_THREAD_BUSY))
                {
                    binding->flags |= _OE_THREAD_BUSY;
                    binding->thread = thread;
                    binding->count = 1;

                    tcs = (void*)binding->tcs;

                    /* Set into TSD so asynchronous exceptions can get it */
                    _set_thread_binding(binding);
                    assert(oe_get_thread_binding() == binding);

                    /* Notify the debugger runtime */
                    if (enclave->debug && enclave->debug_enclave != NULL)
                        oe_debug_push_thread_binding(
                            enclave->debug_enclave, (sgx_tcs_t*)tcs);
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
            oe_thread_binding_t* binding = &enclave->bindings[i];

            if ((binding->flags & _OE_THREAD_BUSY) &&
                (void*)binding->tcs == tcs)
            {
                binding->count--;

                /* Notify the debugger runtime */
                if (enclave->debug && enclave->debug_enclave != NULL)
                    oe_debug_pop_thread_binding();

                if (binding->count == 0)
                {
                    binding->flags &= (~_OE_THREAD_BUSY);
                    binding->thread = 0;
                    memset(&binding->event, 0, sizeof(binding->event));
                    _set_thread_binding(NULL);
                    assert(oe_get_thread_binding() == NULL);
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

    oe_log(
        OE_LOG_LEVEL_VERBOSE,
        "%s 0x%x %s: %s\n",
        enclave->path,
        enclave->addr,
        func == OE_ECALL_CALL_ENCLAVE_FUNCTION ? "EDL_ECALL" : "OE_ECALL",
        oe_ecall_str(func));

    /* Perform ECALL or ORET */
    OE_CHECK(_do_eenter(
        enclave,
        tcs,
        OE_AEP_ADDRESS,
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
** oe_switchless_call_enclave_function_by_table_id()
**
** Switchlessly call the enclave function specified by the given table-id and
*function-id.
**
**==============================================================================
*/

static oe_result_t oe_switchless_call_enclave_function_by_table_id(
    oe_enclave_t* enclave,
    uint64_t table_id,
    uint64_t function_id,
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
        args.table_id = table_id;
        args.function_id = function_id;
        args.input_buffer = input_buffer;
        args.input_buffer_size = input_buffer_size;
        args.output_buffer = output_buffer;
        args.output_buffer_size = output_buffer_size;
        args.output_bytes_written = 0;
        args.result = OE_UNEXPECTED;
    }

    /* TODO: @EMumau Perform the Switchless ECALL */
    {
        OE_RAISE(OE_UNSUPPORTED);
    }

    /* Check the result */
    OE_CHECK(args.result);

    *output_bytes_written = args.output_bytes_written;
    result = OE_OK;

done:
    return result;
}

/*
**==============================================================================
**
** oe_switchless_call_enclave_function()
**
** Switchlessly call the enclave function specified by the given function-id in
** the default function table.
**
**==============================================================================
*/
oe_result_t oe_switchless_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return oe_switchless_call_enclave_function_by_table_id(
        enclave,
        OE_UINT64_MAX,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
}
