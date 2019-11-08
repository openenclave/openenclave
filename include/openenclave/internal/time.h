// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_TIME_H
#define _OE_INCLUDE_TIME_H

#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** oe_sleep_msec()
**
**     Sleep for milliseconds. Return 0 on success and -1 if thread
**     interrupted.
**
**==============================================================================
*/

int oe_sleep_msec(uint64_t milliseconds);

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

OE_EXTERNC_END

#endif /* _OE_INCLUDE_TIME_H */
