/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include "sal_unsup.h"
#include <sgx_edger8r.h>
#include <tcps.h>

#include "optee.h"
#undef oe_call_enclave_function

sgx_status_t sgx_optee_ecall(const sgx_enclave_id_t eid,
                             const int index,
                             const void* ocall_table,
                             void* inOutBuffer,
                             size_t inOutBufferLength)
{
    TEEC_Result res;
    TEEC_Operation op;
    struct tcps_optee_context *optee;
    char dummyInOutBuffer[1];
    uint32_t err_origin;

    optee = (struct tcps_optee_context *)eid;
    optee->ocall_table = (optee_ocall_table_t *)ocall_table;

    if (!inOutBuffer) {
        inOutBuffer = dummyInOutBuffer;
        inOutBufferLength = 1;
    }

    op.params[0].value.a = 1;  // Dummy RPC Key

    op.params[1].tmpref.buffer = inOutBuffer;
    op.params[1].tmpref.size = inOutBufferLength;

    op.params[2].tmpref.buffer = inOutBuffer;
    op.params[2].tmpref.size = inOutBufferLength;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INOUT,
                                     TEEC_NONE);

    res = TEEC_InvokeCommand(&optee->session, (uint32_t)(V1_FUNCTION_ID_OFFSET + index), &op, &err_origin);

    return res == TEEC_SUCCESS ? SGX_SUCCESS : SGX_ERROR_UNEXPECTED;
}

oe_result_t oe_call_internal_enclave_function(
    _In_ oe_enclave_t* enclave,
    _In_ uint32_t function_id,
    _In_reads_bytes_(input_buffer_size) const void* input_buffer,
    _In_ size_t input_buffer_size,
    _Out_writes_bytes_to_(output_buffer_size, *output_bytes_written) void* output_buffer,
    _In_ size_t output_buffer_size,
    _Out_opt_ size_t* output_bytes_written)
{
    TEEC_Result res;
    TEEC_Operation op;
    struct tcps_optee_context *optee;
    char dummyInOutBuffer[1];
    uint32_t err_origin;

    optee = (struct tcps_optee_context *)enclave;

    if (input_buffer == NULL) {
        input_buffer = dummyInOutBuffer;
        input_buffer_size = 1;
    }

    if (output_buffer == NULL) {
        output_buffer = dummyInOutBuffer;
        output_buffer_size = 1;
    }

    op.params[0].value.a = 1;  // Dummy RPC Key

    op.params[1].tmpref.buffer = (void *)input_buffer;
    op.params[1].tmpref.size = input_buffer_size;

    op.params[2].tmpref.buffer = output_buffer;
    op.params[2].tmpref.size = output_buffer_size;

    op.paramTypes = TEEC_PARAM_TYPES(TEEC_VALUE_INPUT,
                                     TEEC_MEMREF_TEMP_INPUT,
                                     TEEC_MEMREF_TEMP_INOUT,
                                     TEEC_NONE);

    res = TEEC_InvokeCommand(&optee->session, function_id, &op, &err_origin);

    if (output_bytes_written)
        *output_bytes_written = output_buffer_size;

    return res == TEEC_SUCCESS ? OE_OK : OE_UNEXPECTED;
}

oe_result_t oe_call_enclave_function(
    _In_ oe_enclave_t* enclave,
    _In_ uint32_t function_id,
    _In_reads_bytes_(input_buffer_size) const void* input_buffer,
    _In_ size_t input_buffer_size,
    _Out_writes_bytes_to_(output_buffer_size, *output_bytes_written) void* output_buffer,
    _In_ size_t output_buffer_size,
    _Out_opt_ size_t* output_bytes_written)
{
    return oe_call_internal_enclave_function(enclave,
                                             (uint32_t)(V2_FUNCTION_ID_OFFSET + function_id),
                                             input_buffer,
                                             input_buffer_size,
                                             output_buffer,
                                             output_buffer_size,
                                             output_bytes_written);
}
