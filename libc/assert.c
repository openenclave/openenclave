// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

/* Called by assert(condition) when the condition is zero-valued. */
void __assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* func)
{
    /* Delegate to __oe_assert_fail(), which prints a backtrace. */
    __oe_assert_fail(expr, file, line, func);
}
