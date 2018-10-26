/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/host.h>
#include "TcpsCalls_u.h"
#include "oeresult.h"
extern int g_serialize_ecalls;

oe_result_t oe_call_enclave_function( 
    _In_ oe_enclave_t* enclave,
    _In_ uint32_t function_id,
    _In_reads_bytes_(input_buffer_size) void* input_buffer,
    _In_ size_t input_buffer_size,
    _Out_writes_bytes_to_(output_buffer_size, *output_bytes_written) void* output_buffer,
    _In_ size_t output_buffer_size,
    _Out_ size_t* output_bytes_written)
{
    int serialize_ecall = g_serialize_ecalls;
    sgx_status_t sgxStatus = SGX_SUCCESS;

    if (output_buffer_size > 4096) {
        return OE_INVALID_PARAMETER;
    }

    callV2_Result* result = malloc(sizeof(*result));
    if (result == NULL) {
        return OE_OUT_OF_MEMORY;
    }

    sgx_enclave_id_t eid = (sgx_enclave_id_t)enclave;
    buffer4096 inBufferStruct;
    COPY_BUFFER(inBufferStruct, input_buffer, input_buffer_size);

    if (serialize_ecall) {
        oe_acquire_enclave_mutex(enclave);
    }

    sgxStatus = ecall_v2(eid, result, function_id, inBufferStruct, input_buffer_size);

    if (serialize_ecall) {
        oe_release_enclave_mutex(enclave);
    }

    if (sgxStatus == SGX_SUCCESS) {
        memcpy(output_buffer, result->outBuffer, result->outBufferSize);
        *output_bytes_written = result->outBufferSize;
    }
    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    free(result);
    return oeResult;
}
