// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES

#include <openenclave/enclave.h>

#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>
#include "../../common/posix.h"

/* Rename the ecalls table. */
#define __oe_ecalls_table __oe_posix_ecalls_table
#define __oe_ecalls_table_size __oe_posix_ecalls_table_size

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
        OE_POSIX_OCALL_FUNCTION_TABLE_ID,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
}

#include "posix_t.c"

static oe_once_t _once = OE_ONCE_INITIALIZER;

static void _once_function(void)
{
    if (oe_register_ecall_function_table(
            OE_POSIX_ECALL_FUNCTION_TABLE_ID,
            __oe_posix_ecalls_table,
            __oe_posix_ecalls_table_size) != OE_OK)
    {
        const char func[] = "oe_load_module_posix()";
        oe_printf("%s(%u): %s(): failed\n", __FILE__, __LINE__, func);
        oe_abort();
    }
}

oe_result_t oe_load_module_posix(void)
{
    oe_once(&_once, _once_function);
    return OE_OK;
}
