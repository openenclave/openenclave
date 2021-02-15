// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>
#include <openenclave/internal/raise.h>

#include "calls.h"
#include "ecall_ids.h"

/*
**==============================================================================
**
** _call_enclave_function_impl()
**
** Call the enclave function specified by the given function-id.
**
**==============================================================================
*/

static oe_result_t _call_enclave_function_impl(
    oe_enclave_t* enclave,
    uint64_t function_id,
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
/*
**==============================================================================
**
** oe_call_enclave_function()
**
** Call the enclave function specified by the given function-id in the default
** function table.
**
**==============================================================================
*/

oe_result_t oe_call_enclave_function(
    oe_enclave_t* enclave,
    uint64_t* global_id,
    const char* name,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    oe_result_t result = OE_UNEXPECTED;
    uint64_t function_id = OE_UINT64_MAX;

    /*
     * Look up the function id from the per-enclave table based on the
     * global id. The global id is defined as a static variable in the
     * oeedger8r-generated code. The function initializes the global id in
     * the first invocation and uses the cached global id for the subsequent
     * invocations.
     */
    OE_CHECK(oe_get_ecall_ids(enclave, name, global_id, &function_id));

    result = _call_enclave_function_impl(
        enclave,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
done:
    return result;
}
