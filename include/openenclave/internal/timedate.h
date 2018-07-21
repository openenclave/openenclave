// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INCLUDE_TIMEDATE_H
#define _OE_INCLUDE_TIMEDATE_H

#include <openenclave/bits/types.h>

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

typedef struct _oe_sleep_ocall_args
{
    int ret;
    uint64_t milliseconds;
} oe_sleep_ocall_args_t;

int oe_sleep_ocall(uint64_t milliseconds);

/*
**==============================================================================
**
** oe_untrusted_time_ocall()
**
**     Return microseconds elapsed since the Epoch (12:00 AM on 1970/01/01)
**     or return 0 on error.
**
**==============================================================================
*/

uint64_t oe_untrusted_time_ocall(void);

#endif /* _OE_INCLUDE_TIMEDATE_H */
