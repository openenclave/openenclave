// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_TIME_H
#define _OE_INCLUDE_TIME_H

#include <openenclave/bits/types.h>

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
