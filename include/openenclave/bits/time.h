// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_TIME_H
#define _OE_TIME_H

#include <openenclave/types.h>

#if defined(__linux__)
#include <sys/time.h>
#elif defined(_WIN32)
typedef int32_t clockid_t;
#endif
#include <time.h>

/*
**==============================================================================
**
** OE_StrftimeArgs
**
**     size_t strftime(
**         char *str,
**         size_t max,
**         const char *format,
**         const struct tm *tm);
**
**==============================================================================
*/
typedef struct _OE_StrftimeArgs
{
    size_t ret;
    char str[256];
    char format[256];
    struct tm tm;
} OE_StrftimeArgs;

/*
**==============================================================================
**
** OE_GettimeofdayArgs
**
**     int gettimeofday(struct timeval *tv, struct timezone *tz)
**
**==============================================================================
*/
typedef struct _OE_GettimeofdayArgs
{
    int ret;
    struct timeval* tv;
    struct timeval tvbuf;
    struct timezone* tz;
    uint64_t tzbuf[2];
} OE_GettimeofdayArgs;

/*
**==============================================================================
**
** OE_ClockgettimeArgs
**
**     int clock_gettime(clockid_t clk_id, struct timespec *tp);
**
**==============================================================================
*/
typedef struct _OE_ClockgettimeArgs
{
    int ret;
    clockid_t clk_id;
    struct timespec* tp;
    struct timespec tpbuf;
} OE_ClockgettimeArgs;

/*
**==============================================================================
**
** OE_NanosleepArgs
**
**     int nanosleep(const struct timespec *req, struct timespec *rem);
**
**==============================================================================
*/
typedef struct _OE_NanosleepArgs
{
    int ret;
    const struct timespec* req;
    struct timespec reqbuf;
    struct timespec* rem;
    struct timespec rembuf;
} OE_NanosleepArgs;

#endif /* _OE_TIME_H */
