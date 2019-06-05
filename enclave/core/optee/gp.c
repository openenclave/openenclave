// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include "../atexit.h"
#include "../calls.h"
#include "init.h"

#include <tee_internal_api.h>

#define HILO_U64(hi, lo) ((((uint64_t)(hi)) << 32) | (lo))

uint8_t __oe_initialized = 0;

static void _handle_init_enclave(void)
{
    oe_call_init_functions();

    __oe_initialized = 1;
}

static TEE_Result _handle_call_enclave_function(
    uint32_t param_types,
    TEE_Param params[4])
{
    oe_result_t result = OE_OK;

    uint32_t param_type_first;
    uint32_t param_type_second;
    uint32_t param_type_third;
    uint32_t param_type_fourth;

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
    param_type_first = TEE_PARAM_TYPE_GET(param_types, 0);
    param_type_second = TEE_PARAM_TYPE_GET(param_types, 1);
    param_type_third = TEE_PARAM_TYPE_GET(param_types, 2);
    param_type_fourth = TEE_PARAM_TYPE_GET(param_types, 3);

    /* Assert the parameter types are what we expect */
    if (param_type_first != TEE_PARAM_TYPE_NONE &&
        param_type_first != TEE_PARAM_TYPE_VALUE_INPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (param_type_second != TEE_PARAM_TYPE_MEMREF_INOUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (param_type_third != TEE_PARAM_TYPE_NONE &&
        param_type_third != TEE_PARAM_TYPE_MEMREF_INPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    if (param_type_fourth != TEE_PARAM_TYPE_NONE &&
        param_type_fourth != TEE_PARAM_TYPE_MEMREF_OUTPUT)
        return TEE_ERROR_BAD_PARAMETERS;

    /* On Windows, the OP-TEE miniport driver requires a key to associate an
     * OCALL with the ECALL whence it originates, so see if we have one and
     * save it if we do to use it when sending an OCALL out */
    if (param_type_first == TEE_PARAM_TYPE_VALUE_INPUT)
        __oe_windows_ecall_key = params[0].value.a;

    /* Copy the ECALL arguments structure into TA memory */
    if (params[1].memref.size != sizeof(oe_call_enclave_function_args_t))
        return TEE_ERROR_BAD_PARAMETERS;

    u_args_ptr = (oe_call_enclave_function_args_t*)params[1].memref.buffer;
    args = *u_args_ptr;

    /* Extract the input parameters buffer, if present */
    if (param_type_third == TEE_PARAM_TYPE_MEMREF_INPUT)
    {
        u_input_buffer = params[2].memref.buffer;
        u_input_buffer_size = params[2].memref.size;
    }

    /* Extract the output parameters buffer, if present */
    if (param_type_fourth == TEE_PARAM_TYPE_MEMREF_OUTPUT)
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

}

TEE_Result TA_CreateEntryPoint(void)
{
    _handle_init_enclave();

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
        case OE_ECALL_GET_SGX_REPORT:
        {
            result = TEE_ERROR_NOT_IMPLEMENTED;
            break;
        }
        case OE_ECALL_VERIFY_REPORT:
        {
            result = TEE_ERROR_NOT_IMPLEMENTED;
            break;
        }
        case OE_ECALL_LOG_INIT:
        {
            result = TEE_ERROR_NOT_IMPLEMENTED;
            break;
        }
        case OE_ECALL_GET_PUBLIC_KEY_BY_POLICY:
        {
            result = TEE_ERROR_NOT_IMPLEMENTED;
            break;
        }
        case OE_ECALL_GET_PUBLIC_KEY:
        {
            result = TEE_ERROR_NOT_IMPLEMENTED;
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
    /* Call functions installed by __cxa_atexit() and oe_atexit() */
    oe_call_atexit_functions();

    /* Call all finalization functions */
    oe_call_fini_functions();
}
