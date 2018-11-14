// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_TIME_H
#define _ELIBC_TIME_H

#include "bits/common.h"
#include "sys/time.h"

ELIBC_EXTERNC_BEGIN

struct elibc_tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

struct elibc_timespec
{
    time_t tv_sec;
    long tv_nsec;
};

time_t elibc_time(time_t* tloc);

struct elibc_tm* elibc_gmtime(const time_t* timep);

struct elibc_tm* elibc_gmtime_r(
    const time_t* timep,
    struct elibc_tm* result);

#if defined(ELIBC_NEED_STDC_NAMES)

struct tm
{
    int tm_sec;
    int tm_min;
    int tm_hour;
    int tm_mday;
    int tm_mon;
    int tm_year;
    int tm_wday;
    int tm_yday;
    int tm_isdst;
};

struct timespec
{
    time_t tv_sec;
    long tv_nsec;
};

ELIBC_INLINE
time_t time(time_t* tloc)
{
    return elibc_time(tloc);
}

ELIBC_INLINE
struct tm* gmtime(const time_t* timep)
{
    return (struct tm*)elibc_gmtime(timep);
}

ELIBC_INLINE
struct tm* gmtime_r(const time_t* timep, struct tm* result)
{
    return (struct tm*)elibc_gmtime_r(timep, (struct elibc_tm*)result);
}

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

ELIBC_EXTERNC_END

#endif /* _ELIBC_TIME_H */
