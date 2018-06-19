// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _ENCLAVELIBC_COMMON_H
#define _ENCLAVELIBC_COMMON_H

#include "../../enclavelibc.h"

#pragma GCC diagnostic ignored "-Wmissing-prototypes"

#define CHAR_BIT 8

typedef long time_t;
typedef __builtin_va_list va_list;
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

#endif /* _ENCLAVELIBC_COMMON_H */
