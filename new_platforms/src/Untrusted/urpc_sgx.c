/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/host.h>
#include "oeoverintelsgx_u.h"
#include "oeresult.h"
#undef oe_call_enclave_function
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
    sgx_enclave_id_t eid = (sgx_enclave_id_t)enclave;

    if (serialize_ecall) {
        oe_acquire_enclave_mutex(enclave);
    }

    sgxStatus = ecall_v2(eid, output_bytes_written, function_id, input_buffer, input_buffer_size, output_buffer, output_buffer_size);

    if (serialize_ecall) {
        oe_release_enclave_mutex(enclave);
    }

    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    return oeResult;
}

oe_result_t oe_call_internal_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    int serialize_ecall = g_serialize_ecalls;
    sgx_status_t sgxStatus = SGX_SUCCESS;
    sgx_enclave_id_t eid = (sgx_enclave_id_t)enclave;

    if (serialize_ecall) {
        oe_acquire_enclave_mutex(enclave);
    }

    sgxStatus = ecall_internal(eid, output_bytes_written, function_id, input_buffer, input_buffer_size, output_buffer, output_buffer_size);

    if (serialize_ecall) {
        oe_release_enclave_mutex(enclave);
    }

    oe_result_t oeResult = GetOEResultFromSgxStatus(sgxStatus);
    return oeResult;
}
