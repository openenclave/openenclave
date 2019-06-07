// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_TIME_H
#define _OE_SYSCALL_SYS_TIME_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

struct oe_timeval
{
    time_t tv_sec;       /* seconds */
    suseconds_t tv_usec; /* microseconds */
};

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_TIME_H */
