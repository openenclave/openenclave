// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <windows.h>
#include <string.h>
#include <time.h>
#include <openenclave/internal/time.h>

void GetSystemTime(LPSYSTEMTIME p)
{
    struct tm tm;
    uint64_t t;
    time_t time;

    memset(p, 0, sizeof(*p));

    t = oe_get_time();
    time = t / 1000;

    if (gmtime_r(&time, &tm))
    {
        p->wYear = tm.tm_year;
        p->wMonth = tm.tm_mon;
        p->wDayOfWeek = tm.tm_wday;
        p->wDay = tm.tm_mday;
        p->wHour = tm.tm_hour;
        p->wMinute = tm.tm_min;
        p->wSecond = tm.tm_sec;
        p->wMilliseconds = t % 1000;
    }
}
