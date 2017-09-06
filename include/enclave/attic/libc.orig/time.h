#ifndef __ELIBC_TIME_H
#define __ELIBC_TIME_H

#include <features.h>
#include <bits/alltypes.h>
#include <sys/time.h>

__ELIBC_BEGIN

#define CLOCK_REALTIME 0
size_t strftime(char *s, size_t max, const char *format, const struct tm *tm);

#define CLOCK_REALTIME           0
#define CLOCK_MONOTONIC          1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID  3
#define CLOCK_MONOTONIC_RAW      4
#define CLOCK_REALTIME_COARSE    5
#define CLOCK_MONOTONIC_COARSE   6
#define CLOCK_BOOTTIME           7
#define CLOCK_REALTIME_ALARM     8
#define CLOCK_BOOTTIME_ALARM     9
#define CLOCK_SGI_CYCLE         10
#define CLOCK_TAI               11

int clock_gettime(clockid_t clk_id, struct timespec *tp);

int nanosleep(const struct timespec *req, struct timespec *rem);

time_t time(time_t *tloc);

#ifdef __ELIBC_UNSUPPORTED
struct tm *gmtime(const time_t *timep);
#endif

#ifdef __ELIBC_UNSUPPORTED
struct tm *gmtime_r(const time_t *timep, struct tm *result);
#endif

#ifdef __ELIBC_UNSUPPORTED
struct tm *localtime(const time_t *timep);
#endif

__ELIBC_END

#endif /* __ELIBC_TIME_H */
