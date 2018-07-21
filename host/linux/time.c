// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <errno.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/time.h>
#include "../ocalls.h"

/* Return the microseconds elapsed since the Epoch. */
static uint64_t _time()
{
    struct timespec ts;

    if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
        return 0;

    return ((uint64_t)ts.tv_sec * 1000000UL) + ((uint64_t)ts.tv_nsec / 1000UL);
}

static void _sleep(uint64_t milliseconds)
{
    struct timespec ts;
    const struct timespec* req = &ts;
    struct timespec rem = {0, 0};

    ts.tv_sec = (time_t)(milliseconds / 1000UL);
    ts.tv_nsec = (long)((milliseconds % 1000UL) * 1000000UL);

    while (nanosleep(req, &rem) != 0 && errno == EINTR)
    {
        req = &rem;
    }
}

void oe_handle_sleep_ocall(uint64_t arg_in)
{
    const uint64_t milliseconds = arg_in;
    _sleep(milliseconds);
}

void oe_handle_untrusted_time_ocall(uint64_t arg_in, uint64_t* arg_out)
{
    OE_UNUSED(arg_in);

    if (arg_out)
        *arg_out = _time();
}
