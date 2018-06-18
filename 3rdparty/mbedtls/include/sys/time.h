#ifndef _OE_MBEDTLS_SYS_TIME_H
#define _OE_MBEDTLS_SYS_TIME_H

#include <bits/alltypes.h>

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

#endif /* _OE_MBEDTLS_SYS_TIME_H */
