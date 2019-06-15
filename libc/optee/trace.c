// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/print.h>
#include <stdarg.h>

void trace_printf(
    const char* function,
    int line,
    int level,
    int level_ok,
    const char* fmt,
    ...)
{
    va_list ap;

    oe_host_printf("[%i (%i)] %s:%i ", level, level_ok, function, line);

    va_start(ap, fmt);
    oe_host_vfprintf(0, fmt, ap);
    va_end(ap);
}
