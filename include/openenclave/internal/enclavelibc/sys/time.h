// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_SYS_TIME_H
#define _ENCLAVELIBC_SYS_TIME_H

#include "../bits/common.h"

typedef long suseconds_t;
typedef int clockid_t;

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

#endif /* _ENCLAVELIBC_SYS_TIME_H */
