// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/host.h>

#include <openenclave/edger8r/host.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/posix.h>
#include "hostthread.h"

#if defined(_MSC_VER)
#define st_atime st_atime
#define st_mtime st_mtime
#define st_ctime st_ctime
#endif

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
        OE_POSIX_ECALL_FUNCTION_TABLE_ID,
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

#include "posix_u.c"

static oe_once_type _once = OE_H_ONCE_INITIALIZER;

static void _once_function(void)
{
    if (oe_register_ocall_function_table(
            OE_POSIX_OCALL_FUNCTION_TABLE_ID,
            __posix_ocall_function_table,
            OE_COUNTOF(__posix_ocall_function_table)) != OE_OK)
    {
        const char func[] = "oe_register_posix_ocall_function_table()";

        fprintf(stderr, "%s(%u): %s(): failed\n", __FILE__, __LINE__, func);
        abort();
    }
}

void oe_register_posix_ocall_function_table(void)
{
    oe_once(&_once, _once_function);
}
