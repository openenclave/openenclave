// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define __OE_NEED_TIME_CALLS
#define _GNU_SOURCE
#include <assert.h>
#include <limits.h>
#include <openenclave/bits/calls.h>
#include <openenclave/enclave.h>
#include <stdint.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>

struct tm tm_val;

/* 2000-03-01 (mod 400 year, immediately after feb29 */
#define LEAPOCH (946684800LL + 86400 * (31 + 29))

#define DAYS_PER_400Y (365 * 400 + 97)
#define DAYS_PER_100Y (365 * 100 + 24)
#define DAYS_PER_4Y (365 * 4 + 1)

time_t time(time_t* tloc)
{
    struct timeval tv;

    if (gettimeofday(&tv, NULL) != 0)
        return (time_t)-1;

    if (tloc)
        *tloc = tv.tv_sec;

    return tv.tv_sec;
}
int gmtime_get(const time_t t, struct tm* tm)
{
    long long days, secs;
    int remdays, remsecs, remyears;
    int qc_cycles, c_cycles, q_cycles;
    int years, months;
    int wday, yday, leap;
    static const char days_in_month[] = {
        31, 30, 31, 30, 31, 31, 30, 31, 30, 31, 31, 29};

    /* Reject time_t values whose year would overflow int */
    if (t < INT_MIN * 31622400LL || t > INT_MAX * 31622400LL)
        return -1;

    secs = t - LEAPOCH;
    days = secs / 86400;
    remsecs = secs % 86400;
    if (remsecs < 0)
    {
        remsecs += 86400;
        days--;
    }

    wday = (3 + days) % 7;
    if (wday < 0)
        wday += 7;

    qc_cycles = days / DAYS_PER_400Y;
    remdays = days % DAYS_PER_400Y;
    if (remdays < 0)
    {
        remdays += DAYS_PER_400Y;
        qc_cycles--;
    }

    c_cycles = remdays / DAYS_PER_100Y;
    if (c_cycles == 4)
        c_cycles--;
    remdays -= c_cycles * DAYS_PER_100Y;

    q_cycles = remdays / DAYS_PER_4Y;
    if (q_cycles == 25)
        q_cycles--;
    remdays -= q_cycles * DAYS_PER_4Y;

    remyears = remdays / 365;
    if (remyears == 4)
        remyears--;
    remdays -= remyears * 365;

    leap = !remyears && (q_cycles || !c_cycles);
    yday = remdays + 31 + 28 + leap;
    if (yday >= 365 + leap)
        yday -= 365 + leap;

    years = remyears + 4 * q_cycles + 100 * c_cycles + 400 * qc_cycles;

    for (months = 0; days_in_month[months] <= remdays; months++)
        remdays -= days_in_month[months];

    if (years + 100 > INT_MAX || years + 100 < INT_MIN)
        return -1;

    tm->tm_year = years + 100;
    tm->tm_mon = months + 2;
    if (tm->tm_mon >= 12)
    {
        tm->tm_mon -= 12;
        tm->tm_year++;
    }
    tm->tm_mday = remdays + 1;
    tm->tm_wday = wday;
    tm->tm_yday = yday;

    tm->tm_hour = remsecs / 3600;
    tm->tm_min = remsecs / 60 % 60;
    tm->tm_sec = remsecs % 60;
    return 0;
}

struct tm* gmtime(const time_t* timep)
{
    if (gmtime_get(*timep, &tm_val))
        return NULL;
    else
        return &tm_val;
}

#if 0
int gettimeofday(struct timeval* tv, struct timezone* tz)
#else
int gettimeofday(struct timeval* tv, void* tz)
#endif
{
    size_t ret = -1;
    OE_GettimeofdayArgs* args = NULL;

    if (!(args = OE_HostCalloc(1, sizeof(OE_GettimeofdayArgs))))
        goto done;

    args->ret = -1;

    if (tv)
        args->tv = &args->tvbuf;

    if (tz)
        args->tz = NULL;

    if (OE_OCall(
            OE_FUNC_GETTIMEOFDAY,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        goto done;

    if (args->ret == 0)
    {
        if (tv)
            memcpy(tv, &args->tvbuf, sizeof(args->tvbuf));

        if (tz)
            memcpy(tz, &args->tzbuf, sizeof(args->tzbuf));
    }

    ret = args->ret;

done:

    if (args)
        OE_HostFree(args);

    return ret;
}

int clock_gettime(clockid_t clk_id, struct timespec* tp)
{
    size_t ret = -1;
    OE_ClockgettimeArgs* args = NULL;

    if (!(args = OE_HostMalloc(sizeof(OE_ClockgettimeArgs))))
        goto done;

    args->ret = -1;
    args->clk_id = clk_id;
    args->tp = tp ? &args->tpbuf : NULL;

    if (OE_OCall(
            OE_FUNC_CLOCK_GETTIME,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        goto done;

    if (args->ret == 0)
    {
        if (tp)
            memcpy(tp, &args->tpbuf, sizeof(args->tpbuf));
    }

    ret = args->ret;

done:

    if (args)
        OE_HostFree(args);

    return ret;
}

size_t strftime(char* str, size_t max, const char* format, const struct tm* tm)
{
    size_t ret = 0;
    OE_StrftimeArgs* a = NULL;

    if (!str || !format || !tm)
        goto done;

    if (!(a = OE_HostCalloc(1, sizeof(OE_StrftimeArgs))))
        goto done;

    if (strlcpy(a->format, format, sizeof(a->format)) >= sizeof(a->format))
        goto done;

    memcpy(&a->tm, tm, sizeof(struct tm));

    if (OE_OCall(
            OE_FUNC_STRFTIME, (uint64_t)a, NULL, OE_OCALL_FLAG_NOT_REENTRANT) !=
        OE_OK)
        goto done;

    if (strlcpy(str, a->str, max) >= max)
    {
        *str = '\0';
        goto done;
    }

    ret = a->ret;

done:

    if (a)
        OE_HostFree(a);

    return ret;
}

size_t strftime_l(
    char* s,
    size_t max,
    const char* format,
    const struct tm* tm,
    locale_t loc)
{
    return strftime(s, max, format, tm);
}

int nanosleep(const struct timespec* req, struct timespec* rem)
{
    size_t ret = -1;
    OE_NanosleepArgs* args = NULL;

    if (!(args = OE_HostCalloc(1, sizeof(OE_NanosleepArgs))))
        goto done;

    args->ret = -1;

    if (req)
    {
        memcpy(&args->reqbuf, req, sizeof(args->reqbuf));
        args->req = &args->reqbuf;
    }

    if (rem)
        args->rem = &args->rembuf;

    if (OE_OCall(
            OE_FUNC_NANOSLEEP,
            (uint64_t)args,
            NULL,
            OE_OCALL_FLAG_NOT_REENTRANT) != OE_OK)
        goto done;

    if (args->ret == 0)
    {
        if (rem)
            memcpy(rem, &args->rembuf, sizeof(args->rembuf));
    }

    ret = args->ret;

done:

    if (args)
        OE_HostFree(args);

    return ret;
}
