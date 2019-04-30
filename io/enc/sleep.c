// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/time.h>

unsigned int oe_sleep(unsigned int seconds)
{
    const uint64_t ONE_SECOND = 1000;
    const uint64_t msec = seconds * ONE_SECOND;

    return (oe_sleep_msec(msec) == 0) ? 0 : seconds;
}
