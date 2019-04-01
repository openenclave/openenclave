// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/calls.h>

#define OE_NEED_STDC_NAMES

#define __oe_ecalls_table_size __oe_internal_ecalls_table_size
#define __oe_ecalls_table __oe_internal_ecalls_table
#define oe_call_host_function oe_call_internal_host_function

#include "../../common/oe_t.c"

void public_root_ecall(void)
{
}
