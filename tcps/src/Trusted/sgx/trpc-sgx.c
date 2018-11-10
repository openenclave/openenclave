/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */
#include <openenclave/enclave.h>
#include "oeoverintelsgx_t.h"
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
    sgx_status_t sgxStatus = ocall_v2(output_bytes_written,
                                      function_id,
                                      input_buffer,
                                      input_buffer_size,
                                      output_buffer,
                                      output_buffer_size);
    if (sgxStatus == SGX_SUCCESS) {
        if (*output_bytes_written > output_buffer_size) {
            return OE_BUFFER_TOO_SMALL;
        }
    }
    return GetOEResultFromSgxStatus(sgxStatus);
}
