// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/time.h>
#include <openenclave/internal/timedate.h>
#include "../ocalls.h"

void HandleStrftime(uint64_t argIn)
{
    oe_strftime_args_t* args = (oe_strftime_args_t*)argIn;

    if (!args)
        return;

    args->ret = strftime(args->str, sizeof(args->str), args->format, &args->tm);
}

void HandleGettimeofday(uint64_t argIn)
{
    oe_gettimeofday_args_t* args = (oe_gettimeofday_args_t*)argIn;

    if (!args)
        return;

    args->ret = gettimeofday(args->tv, args->tz);
}

void HandleClockgettime(uint64_t argIn)
{
    oe_clock_gettime_args_t* args = (oe_clock_gettime_args_t*)argIn;

    if (!args)
        return;

    args->ret = clock_gettime(args->clk_id, args->tp);
}

void oe_handle_sleep_ocall(uint64_t arg_in)
{
    oe_sleep_ocall_args_t* args = (oe_sleep_ocall_args_t*)arg_in;
    struct timespec ts;

    if (!args)
        return;

    ts.tv_sec = (time_t)(args->milliseconds / 1000UL);
    ts.tv_nsec = (long)((args->milliseconds % 1000UL) * 1000000UL);

    args->ret = nanosleep(&ts, NULL);
}

void oe_handle_untrusted_time_ocall(uint64_t arg_in, uint64_t* arg_out)
{
    uint64_t ret = 0;

    OE_UNUSED(arg_in);

    /* Get the microseconds elapsed since the Epoch. */
    if (arg_out)
    {
        struct timespec ts;
        uint64_t sec;
        uint64_t usec;

        if (clock_gettime(CLOCK_REALTIME, &ts) != 0)
            goto done;

        sec = ((uint64_t)ts.tv_sec * 1000000UL);
        usec = ((uint64_t)ts.tv_nsec / 1000UL);
        ret = sec + usec;
    }

done:

    if (arg_out)
        *arg_out = ret;
}
