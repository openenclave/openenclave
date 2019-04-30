// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>

#include <openenclave/edger8r/host.h>
#include <openenclave/internal/calls.h>
#include "../../host/hostthread.h"

#if defined(_MSC_VER)
#define st_atime st_atime
#define st_mtime st_mtime
#define st_ctime st_ctime
#endif

/* Override oe_call_enclave_function() calls with _call_enclave_function(). */
#define oe_call_enclave_function _call_enclave_function

/* Use this function below instead of oe_call_enclave_function(). */
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
        OE_ECALL_TABLE_IO,
        function_id,
        input_buffer,
        input_buffer_size,
        output_buffer,
        output_buffer_size,
        output_bytes_written);
}

#include "oeio_u.c"

oe_result_t oe_load_module_io(void)
{
    oe_result_t result = OE_UNEXPECTED;
    static bool _initialized = false;
    static oe_mutex _lock = OE_H_MUTEX_INITIALIZER;

    oe_mutex_lock(&_lock);

    if (!_initialized)
    {
        if (oe_register_ocall_table(
                OE_OCALL_TABLE_IO,
                __oeio_ocall_function_table,
                OE_COUNTOF(__oeio_ocall_function_table)) == OE_OK)
        {
            result = OE_FAILURE;
            goto done;
        }

        _initialized = true;
    }

    result = OE_OK;

done:

    oe_mutex_unlock(&_lock);

    return result;
}
