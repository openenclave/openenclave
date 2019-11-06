// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>

void __oe_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* function)
{
    oe_host_printf(
        "Assertion failed: %s (%s: %s: %d)\n", expr, file, function, line);
    oe_abort();
}
