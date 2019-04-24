// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/string.h>

OE_INLINE size_t strlen(const char* s)
{
    return oe_strlen(s);
}

/* Rename the ecalls table to __oe_ecalls_table_size. */
#define __oe_ecalls_table_size __oe_internal_ecalls_table_size
#define __oe_ecalls_table __oe_internal_ecalls_table

/* Force generated code to call oe_call_internal_host_function(). */
#define oe_call_host_function oe_call_internal_host_function

#include "oe_t.c"
