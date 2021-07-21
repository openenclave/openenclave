// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "openenclave/bits/time.h"
#include <errno.h>
#include <openenclave/internal/localtime.h>
#include <openenclave/internal/time.h>
#include <time.h>
#include "../ocalls/ocalls.h"
#include "openenclave/bits/types.h"

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_NSEC = 1000000UL;

/* Return milliseconds elapsed since the Epoch. */
static uint64_t _time()
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;

    return ((uint64_t)ts.tv_sec * _SEC_TO_MSEC) +
           ((uint64_t)ts.tv_nsec / _MSEC_TO_NSEC);
}

void oe_handle_get_time(uint64_t arg_in, uint64_t* arg_out)
{
    OE_UNUSED(arg_in);

    if (arg_out)
        *arg_out = _time();
}

int oe_localtime(time_t* timep, struct tm* result)
{
    return !localtime_r(timep, result);
}

int oe_syscall_clock_gettime_ocall(oe_clockid_t clockid, oe_timespec* tp)
{
    struct timespec ts;
    int ret = -1;
    switch (clockid)
    {
        case CLOCK_REALTIME:
        case CLOCK_MONOTONIC:
        case CLOCK_PROCESS_CPUTIME_ID:
        case CLOCK_THREAD_CPUTIME_ID:
            break;
        default:
            errno = EINVAL;
            goto done;
    }
    ret = clock_gettime(clockid, &ts);
    if (ret == 0)
    {
        tp->tv_nsec = ts.tv_nsec;
        tp->tv_sec = ts.tv_sec;
    }
done:
    return ret;
}
