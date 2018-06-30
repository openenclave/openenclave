// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_CORELIBC_TIME_H
#define _OE_CORELIBC_TIME_H

#include "bits/common.h"
#include "sys/time.h"

OE_CORELIBC_EXTERNC_BEGIN

struct oe_tm
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

struct oe_timespec
{
    time_t tv_sec;
    long tv_nsec;
};

time_t oe_time(time_t* tloc);

struct oe_tm* oe_gmtime(const time_t* timep);

struct oe_tm* oe_gmtime_r(const time_t* timep, struct oe_tm* result);

#if !defined(OE_CORELIBC_HIDE_STDC_NAMES)

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

OE_CORELIBC_INLINE
time_t time(time_t* tloc)
{
    return oe_time(tloc);
}

OE_CORELIBC_INLINE
struct tm* gmtime(const time_t* timep)
{
    return (struct tm*)oe_gmtime(timep);
}

OE_CORELIBC_INLINE
struct tm* gmtime_r(const time_t* timep, struct tm* result)
{
    return (struct tm*)oe_gmtime_r(timep, (struct oe_tm*)result);
}

#endif /* !defined(OE_CORELIBC_HIDE_STDC_NAMES) */

OE_CORELIBC_EXTERNC_END

#endif /* _OE_CORELIBC_TIME_H */
