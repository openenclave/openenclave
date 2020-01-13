// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <execinfo.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <stdlib.h>

int backtrace(void** buffer, int size)
{
    return oe_backtrace_impl(__builtin_frame_address(0), buffer, size);
}

char** backtrace_symbols(void* const* buffer, int size)
{
    return oe_backtrace_symbols_impl(buffer, size, malloc, realloc, free);
}
