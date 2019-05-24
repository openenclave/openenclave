// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/defs.h>
#include <openenclave/edger8r/enclave.h>

oe_result_t oe_ocall(uint16_t func, uint64_t arg_in, uint64_t* arg_out)
{
    OE_UNUSED(func);
    OE_UNUSED(arg_in);
    OE_UNUSED(arg_out);
    return OE_UNSUPPORTED;
}

oe_result_t oe_call_host_function(
    size_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    OE_UNUSED(function_id);
    OE_UNUSED(input_buffer);
    OE_UNUSED(input_buffer_size);
    OE_UNUSED(output_buffer);
    OE_UNUSED(output_buffer_size);
    OE_UNUSED(output_bytes_written);
    return OE_UNSUPPORTED;
}

void oe_abort(void)
{
    // TODO: Determine the appropriate call to make into OP-TEE on TA abort.
    while (1)
        ;
}
