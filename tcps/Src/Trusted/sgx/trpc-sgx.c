/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include "TcpsCalls_t.h"
#include "oeresult.h"
#include <string.h>

oe_result_t oe_call_host_function(
    size_t function_id,
    void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    callV2_Result result;
    oe_buffer4096 inBufferStruct;
    if (input_buffer_size > sizeof(inBufferStruct)) {
        return OE_INVALID_PARAMETER;
    }
    COPY_BUFFER(inBufferStruct, input_buffer, input_buffer_size);
    sgx_status_t sgxStatus = ocall_v2(&result,
                                      function_id,
                                      inBufferStruct,
                                      input_buffer_size);
    if (sgxStatus == SGX_SUCCESS) {
        if (result.outBufferSize > output_buffer_size) {
            return OE_BUFFER_TOO_SMALL;
        }
        memcpy(output_buffer, result.outBuffer, result.outBufferSize);
        *output_bytes_written = result.outBufferSize;
    }
    return GetOEResultFromSgxStatus(sgxStatus);
}
