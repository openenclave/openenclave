// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

// MUSL gmtime_r.c depends on these variable definitions.
const char __gmt[] = "GMT";

size_t strftime(char* s, size_t max, const char* format, const struct tm* tm)
{
    (void)(s);
    (void)(max);
    (void)(format);
    (void)(tm);
    assert("strftime(): panic" == NULL);
    return 0;
}

size_t strftime_l(
    char* s,
    size_t max,
    const char* format,
    const struct tm* tm,
    locale_t loc)
{
    (void)(s);
    (void)(max);
    (void)(format);
    (void)(tm);
    (void)(loc);
    assert("strftime_l(): panic" == NULL);
    return 0;
}
