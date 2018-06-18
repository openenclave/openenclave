#ifndef _OE_MBEDTLS_TIME_H
#define _OE_MBEDTLS_TIME_H

#include "bits/alltypes.h"
#include "bits/mbedtls_libc.h"
#include "sys/time.h"

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

static __inline
time_t time(time_t* tloc)
{
    return __mbedtls_libc.time(tloc);
}

static __inline
struct tm* gmtime(const time_t* timep)
{
    return __mbedtls_libc.gmtime(timep);
}

#endif /* _OE_MBEDTLS_TIME_H */
