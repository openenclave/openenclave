#ifndef __ELIBC_SYS_TIME_H
#define __ELIBC_SYS_TIME_H

#include <features.h>
#include <bits/alltypes.h>

__ELIBC_BEGIN

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

int gettimeofday(struct timeval* tv, struct timezone* tz);

__ELIBC_END

#endif /* __ELIBC_SYS_TIME_H */
