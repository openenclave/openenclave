// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_TIME_H
#define _OE_TIME_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/time.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

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

time_t oe_time(time_t* tloc);

struct oe_tm* oe_gmtime(const time_t* timep);

struct oe_tm* oe_gmtime_r(const time_t* timep, struct oe_tm* result);

#if defined(OE_NEED_STDC_NAMES)

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

OE_INLINE
time_t time(time_t* tloc)
{
    return oe_time(tloc);
}

OE_INLINE
struct tm* gmtime(const time_t* timep)
{
    return (struct tm*)oe_gmtime(timep);
}

OE_INLINE
struct tm* gmtime_r(const time_t* timep, struct tm* result)
{
    return (struct tm*)oe_gmtime_r(timep, (struct oe_tm*)result);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_TIME_H */
