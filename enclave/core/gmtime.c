// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/bits/types.h>
#include <openenclave/corelibc/time.h>

int __secs_to_tm(long long, struct oe_tm*);

struct oe_tm* oe_gmtime(const time_t* timep)
{
    static struct oe_tm _tm;
    return oe_gmtime_r(timep, &_tm);
}

struct oe_tm* oe_gmtime_r(const time_t* timep, struct oe_tm* result)
{
    if (!timep || !result || __secs_to_tm(*timep, (struct oe_tm*)result) != 0)
        return NULL;

    result->tm_isdst = 0;

    return result;
}
