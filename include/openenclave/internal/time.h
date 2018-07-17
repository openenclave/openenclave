// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_TIME_H
#define _OE_INCLUDE_TIME_H

#include <openenclave/bits/types.h>

#if defined(__linux__)
#include <sys/time.h>
#elif defined(_WIN32)
typedef int32_t clockid_t;
#include <Windows.h>
#endif
#include <time.h>

/*
**==============================================================================
**
** oe_strftime_args_t
**
**     size_t strftime(
**         char *str,
**         size_t max,
**         const char *format,
**         const struct tm *tm);
**
**==============================================================================
*/
typedef struct _oe_strftime_args
{
    size_t ret;
    char str[256];
    char format[256];
    struct tm tm;
} oe_strftime_args_t;

/*
**==============================================================================
**
** oe_gettimeofday_args_t
**
**     int gettimeofday(struct timeval *tv, struct timezone *tz)
**
**==============================================================================
*/
typedef struct _oe_gettimeofday_args
{
    int ret;
    struct timeval* tv;
    struct timeval tvbuf;
    struct timezone* tz;
    uint64_t tzbuf[2];
} oe_gettimeofday_args_t;

/*
**==============================================================================
**
** oe_clock_gettime_args_t
**
**     int clock_gettime(clockid_t clk_id, struct timespec *tp);
**
**==============================================================================
*/
typedef struct _oe_clockgettime_args
{
    int ret;
    clockid_t clk_id;
    struct timespec* tp;
    struct timespec tpbuf;
} oe_clock_gettime_args_t;

/*
**==============================================================================
**
** oe_nanosleep_args_t
**
**     int nanosleep(const struct timespec *req, struct timespec *rem);
**
**==============================================================================
*/
typedef struct _oe_nanosleep_args
{
    int ret;
    const struct timespec* req;
    struct timespec reqbuf;
    struct timespec* rem;
    struct timespec rembuf;
} oe_nanosleep_args_t;

#endif /* _OE_INCLUDE_TIME_H */
