// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/enclave.h>
#include <stdlib.h>
#include <sys/time.h>
#include <time.h>

// MUSL gmtime_r.c depends on these variable definitions.
const char __gmt[] = "GMT";

size_t strftime(char* s, size_t max, const char* format, const struct tm* tm)
{
    OE_UNUSED(s);
    OE_UNUSED(max);
    OE_UNUSED(format);
    OE_UNUSED(tm);
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
    OE_UNUSED(s);
    OE_UNUSED(max);
    OE_UNUSED(format);
    OE_UNUSED(tm);
    OE_UNUSED(loc);
    assert("strftime_l(): panic" == NULL);
    return 0;
}
