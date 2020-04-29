// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/host.h>

#include <openenclave/edger8r/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>

/* Override oe_call_enclave_function() with _call_platform_enclave_function().
 */
#define oe_call_enclave_function _call_platform_enclave_function

/* The ocall edge routines will use this function to route ecalls. */
static oe_result_t _call_platform_enclave_function(
    oe_enclave_t* enclave,
    uint32_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return oe_call_enclave_function_by_table_id(
        enclave,
        OE_SGX_ECALL_FUNCTION_TABLE_ID,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
}

/* Include the oeedger8r generated C file. The macros defined above customize
 * the generated code for internal use. */
#include "platform_u.c"

/* Registers the sgx OCALL function table. */
oe_result_t oe_register_platform_ocall_function_table(void)
{
    const uint64_t table_id = OE_SGX_OCALL_FUNCTION_TABLE_ID;
    const oe_ocall_func_t* ocalls = __platform_ocall_function_table;
    const size_t num_ocalls = OE_COUNTOF(__platform_ocall_function_table);

    return oe_register_ocall_function_table(table_id, ocalls, num_ocalls);
}
