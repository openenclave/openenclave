// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/raise.h>

#include "calls.h"

/*
**==============================================================================
**
** oe_call_enclave_function()
**
** Call the enclave function specified by the given function-id in the
** function table.
**
**==============================================================================
*/

oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_call_enclave_function_args_t args;

    /* Reject invalid parameters */
    if (!enclave)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize the call_enclave_args structure */
    {
        args.function_id = function_id;
        args.input_buffer = input_buffer;
        args.input_buffer_size = input_buffer_size;
        args.output_buffer = output_buffer;
        args.output_buffer_size = output_buffer_size;
        args.output_bytes_written = 0;
        args.result = OE_UNEXPECTED;
    }

    /* Perform the ECALL */
    {
        uint64_t arg_out = 0;

        OE_CHECK(oe_ecall(
            enclave,
            OE_ECALL_CALL_ENCLAVE_FUNCTION,
            (uint64_t)&args,
            &arg_out));
        OE_CHECK((oe_result_t)arg_out);
    }

    /* Check the result */
    OE_CHECK(args.result);

    *output_bytes_written = args.output_bytes_written;
    result = OE_OK;

done:
    return result;
}
