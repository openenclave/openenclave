// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/edger8r/host.h>
#include <stdint.h>

oe_result_t oe_create_enclave(
    const char* enclave_path,
    oe_enclave_type_t enclave_type,
    uint32_t flags,
    const void* config,
    uint32_t config_size,
    const oe_ocall_func_t* ocall_table,
    uint32_t ocall_table_size,
    oe_enclave_t** enclave_out)
{
    OE_UNUSED(enclave_path);
    OE_UNUSED(enclave_type);
    OE_UNUSED(flags);
    OE_UNUSED(config);
    OE_UNUSED(config_size);
    OE_UNUSED(ocall_table);
    OE_UNUSED(ocall_table_size);
    OE_UNUSED(enclave_out);

    return OE_UNSUPPORTED;
}

oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    OE_UNUSED(enclave);
    OE_UNUSED(function_id);
    OE_UNUSED(input_buffer);
    OE_UNUSED(input_buffer_size);
    OE_UNUSED(output_buffer);
    OE_UNUSED(output_buffer_size);
    OE_UNUSED(output_bytes_written);

    return OE_UNSUPPORTED;
}

oe_result_t oe_terminate_enclave(oe_enclave_t* enclave)
{
    OE_UNUSED(enclave);
    return OE_UNSUPPORTED;
}
