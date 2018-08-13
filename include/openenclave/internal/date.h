// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_DATE_H
#define _OE_INTERNAL_DATE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Date representation with 1 second precision */
typedef struct _oe_date
{
    uint32_t year;    /* format: 1970, 2018, 2020 */
    uint32_t month;   /* range: 0-11 */
    uint32_t day;     /* range: 1-31 */
    uint32_t hours;   /* range: 0-23 */
    uint32_t minutes; /* range: 0-59 */
    uint32_t seconds; /* range: 0-59 */
} oe_date_t;

OE_EXTERNC_END

#endif /* _OE_INTERNAL_DATE_H */
