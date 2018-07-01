// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/internal/enclavelibc.h>

void __assert_fail(
    const char* expr,
    const char* file,
    int line,
    const char* function)
{
    return __oe_assert_fail(expr, file, line, function);
}
