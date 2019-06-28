// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/optee/opteeproperties.h>
#include <openenclave/enclave.h>

const char trace_ext_prefix[] = "TA";
int trace_level = TRACE_LEVEL;

extern volatile const struct ta_head ta_head;

int tahead_get_trace_level(void)
{
    return TRACE_LEVEL;
}

uintptr_t tahead_get_rva(void)
{
    return ta_head.rva;
}
