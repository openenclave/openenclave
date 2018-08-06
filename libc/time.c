// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/time.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

// This definition is replicated from "musl/src/time/__tz.c" as this file has
// some dependencies on other functions which are not developed for the enclave
// environment so we are defining the variable here to resolve the dependency
// of extern variable in gmtime_r.c.
const char __gmt[] = "GMT";

time_t time(time_t* tloc)
{
    uint64_t usec;

    if ((usec = oe_get_time()) == 0)
        return 0;

    return (time_t)(usec / 1000000UL);
}

int gettimeofday(struct timeval* tv, void* tz)
{
    int ret = -1;
    uint64_t usec;

    if (tv)
        oe_memset(tv, 0, sizeof(struct timeval));

    if (tz)
        oe_memset(tz, 0, sizeof(struct timezone));

    if (!tv)
        goto done;

    if ((usec = oe_get_time()) == 0)
        goto done;

    tv->tv_sec = usec / 1000000UL;
    tv->tv_usec = usec % 1000000UL;

    ret = 0;

done:
    return 0;
}

int clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    int ret = -1;
    uint64_t usec;

    if (!tp)
        goto done;

    if (clk_id != CLOCK_REALTIME)
    {
        /* Only supporting CLOCK_REALTIME */
        oe_assert("clock_gettime(): panic" == NULL);
        goto done;
    }

    if ((usec = oe_get_time()) == 0)
        return -1;

    tp->tv_sec = usec / 1000000UL;
    tp->tv_nsec = (usec % 1000000UL) * 1000UL;

    ret = 0;

done:

    return ret;
}

int nanosleep(const struct timespec* req, struct timespec* rem)
{
    size_t ret = -1;
    uint64_t milliseconds = 0;

    if (rem)
        oe_memset(rem, 0, sizeof(*rem));

    if (!req)
        goto done;

    /* Convert timespec to milliseconds */
    milliseconds += req->tv_sec * 1000UL;
    milliseconds += req->tv_nsec / 1000000UL;

    /* Perform OCALL */
    ret = oe_sleep(milliseconds);

/* ATTN: handle remainders */

done:

    return ret;
}

size_t strftime(char* s, size_t max, const char* format, const struct tm* tm)
{
    oe_assert("strftime(): panic" == NULL);
    return 0;
}

size_t strftime_l(
    char* s,
    size_t max,
    const char* format,
    const struct tm* tm,
    locale_t loc)
{
    oe_assert("strftime_l(): panic" == NULL);
    return 0;
}
