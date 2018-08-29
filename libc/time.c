// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdlib.h>
#include <assert.h>
#include <sys/time.h>
#include <time.h>

// These definitions are replicated from "musl/src/time/__tz.c" as this file has
// some dependencies on other functions which are not developed for the enclave
// environment so we are defining the variable here to resolve the dependency
// of extern variable in gmtime_r.c.
const char __gmt[] = "GMT";
const char __utc[] = "UTC";

size_t strftime(char* s, size_t max, const char* format, const struct tm* tm)
{
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
    assert("strftime_l(): panic" == NULL);
    return 0;
}
