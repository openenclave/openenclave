#ifndef __ELIBC_TIME_H
#define __ELIBC_TIME_H

#include <features.h>
#include <bits/alltypes.h>
#include <sys/time.h>

__ELIBC_BEGIN

#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1

size_t strftime_u(char *s, size_t max, const char *format, const struct tm *tm);

int clock_gettime_u(clockid_t clk_id, struct timespec *tp);

int nanosleep_u(const struct timespec *req, struct timespec *rem);

time_t time_u(time_t *tloc);

#ifdef __ELIBC_UNSUPPORTED
int clock_gettime(clockid_t clk_id, struct timespec *tp);
#endif

#ifdef __ELIBC_UNSUPPORTED
time_t time(time_t *tloc);
#endif

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
