// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define _GNU_SOURCE
#include "libctime.h"
#include <assert.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/time.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

// These definitions are replicated from "musl/src/time/__tz.c" as this file has
// some dependencies on other functions which are not developed for the enclave
// environment so we are defining the variable here to resolve the dependency
// of extern variable in gmtime_r.c.
const char __gmt[] = "GMT";
const char __utc[] = "UTC";

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_USEC = 1000UL;
static const uint64_t _MSEC_TO_NSEC = 1000000UL;

time_t oe_time(time_t* tloc)
{
    uint64_t msec;

    if ((msec = oe_get_time()) == (uint64_t)-1)
        return 0;

    return (time_t)(msec / _SEC_TO_MSEC);
}

int oe_gettimeofday(struct timeval* tv, void* tz)
{
    int ret = -1;
    uint64_t msec;

    if (tv)
        oe_memset(tv, 0, sizeof(struct timeval));

    if (tz)
        oe_memset(tz, 0, sizeof(struct timezone));

    if (!tv)
        goto done;

    if ((msec = oe_get_time()) == (uint64_t)-1)
        goto done;

    tv->tv_sec = msec / _SEC_TO_MSEC;
    tv->tv_usec = msec % _MSEC_TO_USEC;

    ret = 0;

done:
    return ret;
}

int oe_clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    int ret = -1;
    uint64_t msec;

    if (!tp)
        goto done;

    if (clk_id != CLOCK_REALTIME)
    {
        /* Only supporting CLOCK_REALTIME */
        oe_assert("clock_gettime(): panic" == NULL);
        goto done;
    }

    if ((msec = oe_get_time()) == (uint64_t)-1)
        goto done;

    tp->tv_sec = msec / _SEC_TO_MSEC;
    tp->tv_nsec = (msec % _SEC_TO_MSEC) * _MSEC_TO_NSEC;

    ret = 0;

done:

    return ret;
}

int oe_nanosleep(const struct timespec* req, struct timespec* rem)
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
