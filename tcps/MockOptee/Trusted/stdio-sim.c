/* Copyright (c) Microsoft Corporation.  All Rights Reserved. */
#include <stdarg.h>

int printf(
    const char *format,
    ...)
{
    int result;
    va_list vargs;
    va_start(vargs, format);
    result = vprintf(format, vargs);
    va_end(vargs);
    return result;
}
