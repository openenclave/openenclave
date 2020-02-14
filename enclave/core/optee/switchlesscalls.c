// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

// TODO: Switchless calls for op-tee

#include "../switchlesscalls.h"
#include <openenclave/edger8r/enclave.h>
#include <openenclave/enclave.h>

bool oe_is_switchless_initialized()
{
    return false;
}

oe_result_t oe_handle_init_switchless(
    void* host_worker_contexts,
    size_t num_host_workers)
{
    OE_UNUSED(host_worker_contexts);
    OE_UNUSED(num_host_workers);
    return OE_UNSUPPORTED;
}

oe_result_t oe_post_switchless_ocall(oe_call_host_function_args_t* args)
{
    OE_UNUSED(args);
    return OE_UNSUPPORTED;
}

oe_result_t oe_switchless_call_host_function(
    size_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return oe_call_host_function_by_table_id(
        OE_UINT64_MAX,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written,
        true /* switchless */);
}
