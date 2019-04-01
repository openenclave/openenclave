// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#include "../../common/oe_u.c"

const oe_ocall_func_t* oe_get_internal_ocall_function_table(void)
{
    return __oe_ocall_function_table;
}

size_t oe_get_internal_ocall_function_table_size(void)
{
    return OE_COUNTOF(__oe_ocall_function_table);
}
