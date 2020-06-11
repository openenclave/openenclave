// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES
#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/allocator.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/globals.h>
#include <openenclave/internal/raise.h>
#include "../atexit.h"
#include "../calls.h"
#include "../init_fini.h"
#include "core_t.h"

#include <tee_internal_api.h>

#include <pta_rpc.h>

/**
 * TEE Parameter Types used when invoking the Remote Procedure Call Pseudo
 * Trusted Application (RPC PTA). PTAs are extensions of OP-TEE, running in
 * S:EL1 and are accessed via the TA2TA (Trusted Application-to-Trusted
 * Application) API. The TA2TA API is implemented as a system service by OP-TEE
 * and thus requires a system call (ERET) to access; this is done on our behalf
 * by OP-TEE's implementation of the GlobalPlatform TEE Internal Core API in
 * libutee.
 *
 * Each invocation includes four TEE_Param structures, used for the following
 * purposes, by index, then by component:
 *
 * 0: Platform-specific data
 *    Value A: Open Enclave function ID
 *        Not exactly platform-specific, depending on how one looks at it. The
 *        RPC PTA is meant to be generic in terms of the RPCs it executes so
 *        that there be no Open Enclave-specific code in OP-TEE OS. As a
 *        result, it cannot interpret Open Enclave function IDs (i.e.,
 *        OE_OCALL_*). The only command it understands is PTA_RPC_EXECUTE,
 *        meaning execute an RPC call, its underlying semantics
 *        notwithstanding. The Open Enclave function ID is only interpreted by
 *        the host application on the other end of the RPC call. Given that
 *        each of the four parameters can only have one usage, that there are
 *        indeed only four, and that the other three are used, the Open Enclave
 *        function ID is passed through here. The RPC PTA just marshals it out
 *        to non-secure mode as-is.
 *    Value B: OCALL Key
 *        The Windows OP-TEE driver handles RPCs asynchronously and requires a
 *        way to identify each RPC so as to associate it with saved state.
 *        TODO: The driver should be redesigned to not require this.
 *
 * 1: Open Enclave-specific data
 *    Memref: Arguments marshaling structure, if any.
 *        Note: This parameter is not used for built-in OCALLs.
 *
 * 2: Input parameter
 *    Memref: The input parameters buffer, if any.
 *
 * 3: Output parameter
 *    Memref: The output parameters buffer, if any.
 *
 * A similar pattern is used when the host calls into the enclave via an ECALL.
 * There is no reason why the pattern is similar, other than for consistency.
 *
 * See host/optee/linux/enclave.c.
 */

#define PT_BUILTIN_CALL_IN_OUT       \
    (TEE_PARAM_TYPES(                \
        TEE_PARAM_TYPE_VALUE_INPUT,  \
        TEE_PARAM_TYPE_NONE,         \
        TEE_PARAM_TYPE_MEMREF_INPUT, \
        TEE_PARAM_TYPE_MEMREF_OUTPUT))
#define PT_BUILTIN_CALL_IN_NO_OUT    \
    (TEE_PARAM_TYPES(                \
        TEE_PARAM_TYPE_VALUE_INPUT,  \
        TEE_PARAM_TYPE_NONE,         \
        TEE_PARAM_TYPE_MEMREF_INPUT, \
        TEE_PARAM_TYPE_NONE))

#define PT_HOST_CALL_IN_OUT          \
    (TEE_PARAM_TYPES(                \
        TEE_PARAM_TYPE_VALUE_INPUT,  \
        TEE_PARAM_TYPE_MEMREF_INOUT, \
        TEE_PARAM_TYPE_MEMREF_INPUT, \
        TEE_PARAM_TYPE_MEMREF_OUTPUT))
#define PT_HOST_CALL_IN_NO_OUT       \
    (TEE_PARAM_TYPES(                \
        TEE_PARAM_TYPE_VALUE_INPUT,  \
        TEE_PARAM_TYPE_MEMREF_INOUT, \
        TEE_PARAM_TYPE_MEMREF_INPUT, \
        TEE_PARAM_TYPE_NONE))
#define PT_HOST_CALL_NO_IN_OUT       \
    (TEE_PARAM_TYPES(                \
        TEE_PARAM_TYPE_VALUE_INPUT,  \
        TEE_PARAM_TYPE_MEMREF_INOUT, \
        TEE_PARAM_TYPE_NONE,         \
        TEE_PARAM_TYPE_MEMREF_OUTPUT))
#define PT_HOST_CALL_NO_IN_NO_OUT    \
    (TEE_PARAM_TYPES(                \
        TEE_PARAM_TYPE_VALUE_INPUT,  \
        TEE_PARAM_TYPE_MEMREF_INOUT, \
        TEE_PARAM_TYPE_NONE,         \
        TEE_PARAM_TYPE_NONE))

static uint8_t __oe_initialized = 0;
static uint32_t __oe_windows_ecall_key = 0;

static TEE_TASessionHandle __oe_rpc_pta_session = TEE_HANDLE_NULL;

static TEE_Result _handle_call_enclave_function(
    uint32_t param_types,
    TEE_Param params[4])
{
    oe_result_t result = OE_OK;

    uint32_t pt_os;
    uint32_t pt_inout;
    uint32_t pt_in;
    uint32_t pt_out;

    oe_call_enclave_function_args_t args, *u_args_ptr;

    oe_ecall_func_t func;
    ecall_table_t ecall_table;

    const void* u_input_buffer = NULL;
    size_t u_input_buffer_size = 0;

    void* u_output_buffer = NULL;
    size_t u_output_buffer_size = 0;

    void* input_buffer = NULL;
    void* output_buffer = NULL;

    size_t output_bytes_written = 0;

    /* Retrieve the type of the call parameters */
    pt_os = TEE_PARAM_TYPE_GET(param_types, 0);
    pt_inout = TEE_PARAM_TYPE_GET(param_types, 1);
    pt_in = TEE_PARAM_TYPE_GET(param_types, 2);
    pt_out = TEE_PARAM_TYPE_GET(param_types, 3);

    /* Assert the parameter types are what we expect */
    if (pt_os != TEE_PARAM_TYPE_NONE && pt_os != TEE_PARAM_TYPE_VALUE_INPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (pt_inout != TEE_PARAM_TYPE_MEMREF_INOUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (pt_in != TEE_PARAM_TYPE_NONE && pt_in != TEE_PARAM_TYPE_MEMREF_INPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (pt_out != TEE_PARAM_TYPE_NONE && pt_out != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    /* On Windows, the OP-TEE miniport driver requires a key to associate an
     * OCALL with the ECALL whence it originates, so see if we have one and
     * save it if we do to use it when sending an OCALL out */
    if (pt_os == TEE_PARAM_TYPE_VALUE_INPUT)
        __oe_windows_ecall_key = params[0].value.a;

    /* Copy the ECALL arguments structure into TA memory */
    if (params[1].memref.size != sizeof(oe_call_enclave_function_args_t))
        return TEE_ERROR_BAD_PARAMETERS;

    u_args_ptr = (oe_call_enclave_function_args_t*)params[1].memref.buffer;
    args = *u_args_ptr;

    /* Extract the input parameters buffer, if present */
    if (pt_in == TEE_PARAM_TYPE_MEMREF_INPUT)
    {
        u_input_buffer = params[2].memref.buffer;
        u_input_buffer_size = params[2].memref.size;
    }

    /* Extract the output parameters buffer, if present */
    if (pt_out == TEE_PARAM_TYPE_MEMREF_OUTPUT)
    {
        u_output_buffer = params[3].memref.buffer;
        u_output_buffer_size = params[3].memref.size;
    }

    /* Resolve which ECALL table to use. */
    if (args.table_id == OE_UINT64_MAX)
    {
        ecall_table.ecalls = __oe_ecalls_table;
        ecall_table.num_ecalls = __oe_ecalls_table_size;
    }
    else
    {
        if (args.table_id >= OE_MAX_ECALL_TABLES)
            return TEE_ERROR_ITEM_NOT_FOUND;

        ecall_table.ecalls = _ecall_tables[args.table_id].ecalls;
        ecall_table.num_ecalls = _ecall_tables[args.table_id].num_ecalls;

        if (!ecall_table.ecalls)
            return TEE_ERROR_ITEM_NOT_FOUND;
    }

    /* Fetch matching function */
    if (args.function_id >= ecall_table.num_ecalls)
        return TEE_ERROR_ITEM_NOT_FOUND;

    func = ecall_table.ecalls[args.function_id];

    if (func == NULL)
        return TEE_ERROR_ITEM_NOT_FOUND;

    /* Allocate an input buffer in the TA for copy */
    if (u_input_buffer)
    {
        input_buffer = oe_malloc(u_input_buffer_size);
        if (!input_buffer)
            return TEE_ERROR_OUT_OF_MEMORY;
    }

    /* Allocate an output buffer in the TA for copy */
    if (u_output_buffer)
    {
        output_buffer = oe_malloc(u_output_buffer_size);
        if (!output_buffer)
        {
            result = TEE_ERROR_OUT_OF_MEMORY;
            goto done;
        }
    }

    /* Copy the input buffer into the TA */
    if (u_input_buffer)
        memcpy(input_buffer, u_input_buffer, u_input_buffer_size);

    /* Copy the output buffer into the TA */
    if (u_output_buffer)
        memcpy(output_buffer, u_output_buffer, u_output_buffer_size);

    /* Call the function */
    func(
        input_buffer,
        u_input_buffer_size,
        output_buffer,
        u_output_buffer_size,
        &output_bytes_written);

    /* Get the result from the output buffer */
    result = *(oe_result_t*)output_buffer;

    /* Copy outputs to host memory, if necessary */
    if (result == OE_OK && u_output_buffer)
    {
        if (u_output_buffer)
        {
            memcpy(u_output_buffer, output_buffer, output_bytes_written);
            u_args_ptr->output_bytes_written = output_bytes_written;
        }

        u_args_ptr->result = OE_OK;
    }

done:
    /* Free local copies */
    if (input_buffer)
        oe_free(input_buffer);

    if (output_buffer)
        oe_free(output_buffer);

    return result == OE_OK ? TEE_SUCCESS : TEE_ERROR_GENERIC;
}

static oe_result_t _handle_call_builtin_function(
    uint16_t func,
    uint64_t arg_in,
    uint64_t* arg_out)
{
    TEE_Result tee_res;

    TEE_Param params[TEE_NUM_PARAMS];
    uint32_t param_types;

    /* The PTA RPC does not understand Open Enclave function codes */
    params[0].value.a = func;

    /* Host OS-specific data (used only on Windows) */
    params[0].value.b = __oe_windows_ecall_key;

    /* Input buffer */
    params[2].memref.buffer = &arg_in;
    params[2].memref.size = sizeof(arg_in);

    /* Output buffer */
    if (arg_out)
    {
        params[3].memref.buffer = (void*)arg_out;
        params[3].memref.size = sizeof(*arg_out);
    }

    /* Fill in parameter types */
    param_types = arg_out ? PT_BUILTIN_CALL_IN_OUT : PT_BUILTIN_CALL_IN_NO_OUT;

    /* Ask the RPC PTA to perform an OCALL on our behalf via the TA2TA API */
    tee_res = TEE_InvokeTACommand(
        __oe_rpc_pta_session, 0, PTA_RPC_EXECUTE, param_types, params, NULL);

    return tee_res == TEE_SUCCESS ? OE_OK : OE_FAILURE;
}

static oe_result_t _handle_call_host_function(
    oe_call_host_function_args_t* args)
{
    TEE_Result tee_res;

    TEE_Param params[TEE_NUM_PARAMS];
    uint32_t param_types;

    /* The PTA RPC does not understand Open Enclave function codes */
    params[0].value.a = OE_OCALL_CALL_HOST_FUNCTION;

    /* Host OS-specific data (used only on Windows) */
    params[0].value.b = __oe_windows_ecall_key;

    /* Open Enclave-specific data */
    params[1].memref.buffer = args;
    params[1].memref.size = sizeof(*args);

    /* Input buffer */
    if (args->input_buffer)
    {
        if (args->input_buffer_size > OE_UINT32_MAX)
            return OE_OUT_OF_BOUNDS;

        params[2].memref.buffer = (void*)args->input_buffer;
        params[2].memref.size = (uint32_t)args->input_buffer_size;
    }

    /* Output buffer */
    if (args->output_buffer)
    {
        if (args->output_buffer_size > OE_UINT32_MAX)
            return OE_OUT_OF_BOUNDS;

        params[3].memref.buffer = (void*)args->output_buffer;
        params[3].memref.size = (uint32_t)args->output_buffer_size;
    }

    /* Fill in parameter types */
    if (args->input_buffer && args->output_buffer)
        param_types = PT_HOST_CALL_IN_OUT;
    else if (args->input_buffer)
        param_types = PT_HOST_CALL_IN_NO_OUT;
    else if (args->output_buffer)
        param_types = PT_HOST_CALL_NO_IN_OUT;
    else
        param_types = PT_HOST_CALL_NO_IN_NO_OUT;

    /* Ask the RPC PTA to perform an OCALL on our behalf via the TA2TA API */
    tee_res = TEE_InvokeTACommand(
        __oe_rpc_pta_session, 0, PTA_RPC_EXECUTE, param_types, params, NULL);

    return tee_res == TEE_SUCCESS ? OE_OK : OE_FAILURE;
}

oe_result_t oe_ocall(uint16_t func, uint64_t arg_in, uint64_t* arg_out)
{
    oe_result_t result;

    /* Dispatch OCALL based on function */
    if (func == OE_OCALL_CALL_HOST_FUNCTION)
    {
        result =
            _handle_call_host_function((oe_call_host_function_args_t*)arg_in);
    }
    else
    {
        result = _handle_call_builtin_function(func, arg_in, arg_out);
    }

    return result;
}

void oe_abort(void)
{
    /* No return */
    TEE_Panic(TEE_ERROR_GENERIC);

    /**
     * TEE_Panic() does not return, but it is not properly annotated.
     * Ensure the compiler does not return from this function.
     */
    while (1)
        ;
}

TEE_Result TA_CreateEntryPoint(void)
{
    TEE_Result result;

    TEE_UUID pta_uuid = PTA_RPC_UUID;

    /* Initialize the memory allocator */
    oe_allocator_init((void*)__oe_get_heap_base(), (void*)__oe_get_heap_end());
    oe_allocator_thread_init();

    /* Open a TA2TA session against the RPC Pseudo TA (PTA), required for
     * making OCALLs. If we cannot open one, fail to initialize the TA */
    result =
        TEE_OpenTASession(&pta_uuid, 0, 0, NULL, &__oe_rpc_pta_session, NULL);
    if (result != TEE_SUCCESS)
        return result;

    /* Call compiler-generated initialization functions */
    oe_call_init_functions();

#ifdef OE_USE_BUILTIN_EDL
    /* Install the common TEE ECALL function table. */
    if (oe_register_core_ecall_function_table() != OE_OK)
        return TEE_ERROR_GENERIC;
#endif

    /* Done */
    __oe_initialized = 1;

    return TEE_SUCCESS;
}

TEE_Result TA_OpenSessionEntryPoint(
    uint32_t param_types,
    TEE_Param params[4],
    void** sess_ctx)
{
    OE_UNUSED(params);

    uint32_t exp_param_types = TEE_PARAM_TYPES(
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE,
        TEE_PARAM_TYPE_NONE);

    if (param_types != exp_param_types)
    {
        return TEE_ERROR_BAD_PARAMETERS;
    }

    *sess_ctx = NULL;

    return TEE_SUCCESS;
}

TEE_Result TA_InvokeCommandEntryPoint(
    void* sess_ctx,
    uint32_t cmd_id,
    uint32_t param_types,
    TEE_Param params[4])
{
    OE_UNUSED(sess_ctx);

    oe_result_t result = OE_OK;

    switch (cmd_id)
    {
        case OE_ECALL_CALL_ENCLAVE_FUNCTION:
        {
            result = _handle_call_enclave_function(param_types, params);
            break;
        }
        case OE_ECALL_DESTRUCTOR:
        {
            /* Destruction performed by TA_DestroyEntryPoint */
            result = TEE_ERROR_BAD_STATE;
            break;
        }
        case OE_ECALL_VIRTUAL_EXCEPTION_HANDLER:
        {
            result = TEE_ERROR_NOT_IMPLEMENTED;
            break;
        }
        case OE_ECALL_INIT_ENCLAVE:
        {
            /* Initialization performed by TA_CreateEntryPoint */
            result = TEE_ERROR_BAD_STATE;
            break;
        }
        default:
        {
            /* No function found with the number */
            result = TEE_ERROR_ITEM_NOT_FOUND;
            goto done;
        }
    }

done:
    return result;
}

void TA_CloseSessionEntryPoint(void* sess_ctx)
{
    OE_UNUSED(sess_ctx);
}

void TA_DestroyEntryPoint(void)
{
    /* Call functions installed by oe_cxa_atexit() and oe_atexit() */
    oe_call_atexit_functions();

    /* Call all finalization functions */
    oe_call_fini_functions();

    /* Clean up the memory allocator */
    oe_allocator_thread_cleanup();
    oe_allocator_cleanup();
}
