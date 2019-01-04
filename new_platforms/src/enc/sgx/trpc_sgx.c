/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include "oeoverintelsgx_t.h"
#include "oeresult.h"
#include <string.h>
#undef oe_call_host_function

bool oe_is_within_enclave(const void* ptr, size_t size)
{
    return sgx_is_within_enclave(ptr, size);
}

bool oe_is_outside_enclave(const void* ptr, size_t size)
{
    return sgx_is_outside_enclave(ptr, size);
}

oe_result_t oe_call_host_function(
    size_t function_id,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result;
    sgx_status_t sgxStatus = ocall_v2(
        &result,
        (uint32_t)function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
    if (sgxStatus != SGX_SUCCESS) {
        return GetOEResultFromSgxStatus(sgxStatus);
    }
    return result;
}

oe_result_t oe_call_internal_host_function(
    size_t function_id,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result;
    sgx_status_t sgxStatus = ocall_internal(
        &result,
        (uint32_t)function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
    if (sgxStatus != SGX_SUCCESS) {
        return GetOEResultFromSgxStatus(sgxStatus);
    }
    return result;
}
