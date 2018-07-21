// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_TIME_H
#define _OE_INCLUDE_TIME_H

#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** oe_sleep_ocall()
**
**     Sleep for milliseconds. Return 0 on success and -1 if thread 
**     interrupted.
**
**==============================================================================
*/

int oe_sleep_ocall(uint64_t milliseconds);

/*
**==============================================================================
**
** oe_time_ocall()
**
**     Return microseconds elapsed since the Epoch or 0 on error.
**
**     The Epoch is defined as: 1970-01-01 00:00:00 +0000 (UTC)
**
**==============================================================================
*/

uint64_t oe_time_ocall(void);

OE_EXTERNC_END

#endif /* _OE_INCLUDE_TIME_H */
