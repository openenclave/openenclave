// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../enclave/core/posix/epoll.h"

#if !defined(_MSC_VER)
#pragma GCC diagnostic ignored "-Wmissing-prototypes"
#else
#define st_atime st_atime
#define st_mtime st_mtime
#define st_ctime st_ctime
#endif

/* Force generated edger8r code to call oe_call_internal_enclave_function(). */
#define oe_call_enclave_function oe_call_internal_enclave_function

/* Return the statically-defined function call table. */
#include "oe_u.c"

const oe_ocall_func_t* oe_get_internal_ocall_function_table(void)
{
    return __oe_ocall_function_table;
}

/* Return the size of the statically-defined function call table. */
size_t oe_get_internal_ocall_function_table_size(void)
{
    return OE_COUNTOF(__oe_ocall_function_table);
}
