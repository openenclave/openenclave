// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/backtrace.h>
#include <openenclave/internal/print.h>

void __oe_assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* function)
{
    oe_host_printf(
        "Assertion failed: %s (%s: %s: %d)\n", expr, file, function, line);
    oe_print_backtrace();
    oe_abort();
}
