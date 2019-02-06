// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/types.h>

/* Use OE STDC time.h definition for struct tm */
#if !defined(OE_NEED_STDC_NAMES)
#define OE_NEED_STDC_NAMES
#define __UNDEF_OE_NEED_STDC_NAMES
#endif
#include <openenclave/corelibc/time.h>
#if defined(__UNDEF_OE_NEED_STDC_NAMES)
#undef OE_NEED_STDC_NAMES
#undef __UNDEF_OE_NEED_STDC_NAMES
#endif

int __secs_to_tm(long long, struct tm*);

struct oe_tm* oe_gmtime(const time_t* timep)
{
    static struct oe_tm _tm;
    return oe_gmtime_r(timep, &_tm);
}

struct oe_tm* oe_gmtime_r(const time_t* timep, struct oe_tm* result)
{
    if (!timep || !result || __secs_to_tm(*timep, (struct tm*)result) != 0)
        return NULL;

    result->tm_isdst = 0;

    return result;
}
