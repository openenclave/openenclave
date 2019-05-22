// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <stdarg.h>
#include <stdio.h>

void trace_printf(
    const char* function,
    int line,
    int level,
    int level_ok,
    const char* fmt,
    ...)
{
    va_list ap;

    printf("[%i (%i)] %s:%i ", level, level_ok, function, line);

    va_start(ap, fmt);
    vfprintf(stdout, fmt, ap);
    va_end(ap);
}
