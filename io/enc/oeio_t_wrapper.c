// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define OE_NEED_STDC_NAMES

#include <openenclave/enclave.h>

#include <openenclave/corelibc/string.h>
#include <openenclave/edger8r/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/thread.h>

/* Rename the ecalls table. */
#define __oe_ecalls_table __oe_oeio_ecalls_table
#define __oe_ecalls_table_size __oe_oeio_ecalls_table_size

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
        OE_OCALL_TABLE_IO,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
}

#include "oeio_t.c"

oe_result_t oe_load_module_io(void)
{
    oe_result_t result = OE_UNEXPECTED;
    static bool _initialized = false;
    static oe_spinlock_t _lock = OE_SPINLOCK_INITIALIZER;

    oe_spin_lock(&_lock);

    if (!_initialized)
    {
        if (oe_register_ocall_table(
                OE_ECALL_TABLE_IO,
                __oe_oeio_ecalls_table,
                __oe_oeio_ecalls_table_size) != OE_OK)
        {
            result = OE_FAILURE;
            goto done;
        }

        _initialized = true;
    }

    result = OE_OK;

done:

    oe_spin_unlock(&_lock);

    return result;
}
