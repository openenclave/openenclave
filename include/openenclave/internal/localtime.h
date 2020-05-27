// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_LOCALTIME_H
#define _OE_INTERNAL_LOCALTIME_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <time.h>

OE_EXTERNC_BEGIN

/**
 * Return the current system time in local time.
 */
extern int oe_localtime(time_t* timep, struct tm* result);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_DATETIME_H */
