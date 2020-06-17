// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <execinfo.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <stdlib.h>

/**
 * backtrace itself must not appear in the backtrace. It ought to behave as
 * if it was inlined. To keep the implementation private, the function is
 * defined here (which rules out the ability to use compiler's inline keywords)
 * and its frame address is passed to oe_backtrace_impl. oe_backtrace_impl walks
 * the callstack starting at caller of the given frame. This ensures that
 * oe_backtrace is omitted from the backtrace. This scheme also works whether
 * the compiler emits a call or jmp instruction to call oe_backtrace_impl.
 */
int backtrace(void** buffer, int size)
{
    return oe_backtrace_impl(__builtin_frame_address(0), buffer, size);
}

char** backtrace_symbols(void* const* buffer, int size)
{
    return oe_backtrace_symbols_impl(buffer, size, malloc, realloc, free);
}
