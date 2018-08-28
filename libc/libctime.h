// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_LIBC_TIME_H
#define _OE_LIBC_TIME_H

#include <openenclave/enclave.h>
#define _GNU_SOURCE
#include <sys/time.h>
#include <time.h>

time_t oe_time(time_t* tloc);

int oe_gettimeofday(struct timeval* tv, void* tz);

int oe_clock_gettime(clockid_t clk_id, struct timespec* tp);

int oe_nanosleep(const struct timespec* req, struct timespec* rem);

#endif /* _OE_LIBC_TIME_H */
