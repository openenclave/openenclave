// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

/* Force generated edger8r code to call oe_call_internal_enclave_function(). */
#define oe_call_enclave_function oe_call_internal_enclave_function

#include "oe_u.c"

/* Return the statically-defined function call table. */
const oe_ocall_func_t* oe_get_internal_ocall_function_table(void)
{
    return __oe_ocall_function_table;
}

/* Return the size of the statically-defined function call table. */
size_t oe_get_internal_ocall_function_table_size(void)
{
    return OE_COUNTOF(__oe_ocall_function_table);
}
