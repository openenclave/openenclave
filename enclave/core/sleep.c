// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/time.h>

unsigned int oe_sleep(unsigned int seconds)
{
    return (oe_sleep_msec((uint64_t)seconds * 1000) == 0) ? 0 : seconds;
}
