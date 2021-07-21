// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_TIME_H
#define _OE_INCLUDE_TIME_H

#include <openenclave/bits/time.h>
#include <openenclave/bits/types.h>

/*
 * The IDs of the various system clocks (for POSIX.1b interval timers):
 */
#define CLOCK_REALTIME 0
#define CLOCK_MONOTONIC 1
#define CLOCK_PROCESS_CPUTIME_ID 2
#define CLOCK_THREAD_CPUTIME_ID 3
#define CLOCK_MONOTONIC_RAW 4
#define CLOCK_REALTIME_COARSE 5
#define CLOCK_MONOTONIC_COARSE 6
#define CLOCK_BOOTTIME 7
#define CLOCK_REALTIME_ALARM 8
#define CLOCK_BOOTTIME_ALARM 9

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** oe_get_time()
**
**     Return milliseconds elapsed since the Epoch or (uint64_t)-1 on error.
**
**     The Epoch is defined as: 1970-01-01 00:00:00 +0000 (UTC)
**
**==============================================================================
*/

uint64_t oe_get_time(void);

/*
 * Forward declaration of ocall since libc/CMakeLists.txt does not process any
 * EDLs. The code is structured such that if this declaration does not match
 * oeedger8r generated declaration, there will be compile error.
 */
#ifdef OE_BUILD_ENCLAVE
oe_result_t oe_syscall_clock_gettime_ocall(
    int* ret,
    oe_clockid_t clockid,
    oe_timespec* tp);
#else
int oe_syscall_clock_gettime_ocall(oe_clockid_t clockid, oe_timespec* tp);
#endif

#ifdef _WIN32
/*
**==============================================================================
**
** gettimeofday()
**
**     Get seconds and useconds elapsed since the Epoch.
**
**==============================================================================
*/

int gettimeofday(struct timeval* tv, struct timezone* tz);
#endif

OE_EXTERNC_END

#endif /* _OE_INCLUDE_TIME_H */
