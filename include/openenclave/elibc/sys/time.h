// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ELIBC_SYS_TIME_H
#define _ELIBC_SYS_TIME_H

#include "../bits/common.h"

ELIBC_EXTERNC_BEGIN

struct elibc_timeval
{
    time_t tv_sec;
    suseconds_t tv_usec;
};

struct elibc_timezone
{
    int tz_minuteswest;
    int tz_dsttime;
};

#if defined(ELIBC_NEED_STDC_NAMES)

struct timeval
{
    time_t tv_sec;
    suseconds_t tv_usec;
};

struct timezone
{
    int tz_minuteswest;
    int tz_dsttime;
};

#endif /* defined(ELIBC_NEED_STDC_NAMES) */

ELIBC_EXTERNC_END

#endif /* _ELIBC_SYS_TIME_H */
