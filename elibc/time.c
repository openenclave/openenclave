// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/time.h>
#include <time.h>

time_t elibc_time(time_t* tloc)
{
    uint64_t msec = oe_get_time();
    time_t time = (msec / 1000);

    if (tloc)
        *tloc = time;

    return time;
}
