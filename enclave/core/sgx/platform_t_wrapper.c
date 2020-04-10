// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>

/* Rename the global ecalls table. */
#define __oe_ecalls_table __oe_platform_ecalls_table
#define __oe_ecalls_table_size __oe_platform_ecalls_table_size

/* Override oe_call_host_function() calls with _call_host_function(). */
#define oe_call_host_function _call_host_function

/* Use this function below instead of oe_call_host_function(). */
static oe_result_t _call_host_function(
    size_t function_id,
    const void* input_buffer,
    size_t input_buffer_size,
    void* output_buffer,
    size_t output_buffer_size,
    size_t* output_bytes_written)
{
    return oe_call_host_function_by_table_id(
        OE_SGX_OCALL_FUNCTION_TABLE_ID,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written,
        false /* non-switchless */);
}

/* Include the oeedger8r generated C file. The macros defined above customize
 * the generated code for internal use. */
#include "platform_t.c"

/* Registers the sgx ECALL function table. */
oe_result_t oe_register_platform_ecall_function_table(void)
{
    const uint64_t table_id = OE_SGX_ECALL_FUNCTION_TABLE_ID;
    const oe_ecall_func_t* ecalls = __oe_platform_ecalls_table;
    const size_t num_ecalls = __oe_platform_ecalls_table_size;

    return oe_register_ecall_function_table(table_id, ecalls, num_ecalls);
}
