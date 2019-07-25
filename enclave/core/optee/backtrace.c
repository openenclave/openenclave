// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

int oe_backtrace(void** buffer, int size)
{
    OE_UNUSED(size);

    *buffer = NULL;

    return 0;
}

char** oe_backtrace_symbols(void* const* buffer, int size)
{
    OE_UNUSED(buffer);
    OE_UNUSED(size);

    return NULL;
}

void oe_backtrace_symbols_free(char** ptr)
{
    OE_UNUSED(ptr);
}
