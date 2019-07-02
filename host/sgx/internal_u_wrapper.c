// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>

#include <openenclave/edger8r/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/raise.h>

/* Override oe_call_enclave_function() calls with _call_enclave_function(). */
#define oe_call_enclave_function _call_enclave_function

/* The ocall edge routines will use this function to route ecalls. */
static oe_result_t _call_enclave_function(
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
        OE_INTERNAL_ECALL_FUNCTION_TABLE_ID,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
}

/* Ignore missing edge-routine prototypes. */
#if defined(__GNUC__)
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#endif

/* Include the generated source. */
#include "internal_u.c"

/* Registers the internal OCALL function table. */
oe_result_t oe_register_internal_ocall_function_table(void)
{
    const uint64_t table_id = OE_INTERNAL_OCALL_FUNCTION_TABLE_ID;
    const oe_ocall_func_t* ocalls = __internal_ocall_function_table;
    const size_t num_ocalls = OE_COUNTOF(__internal_ocall_function_table);

    return oe_register_ocall_function_table(table_id, ocalls, num_ocalls);
}
