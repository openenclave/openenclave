// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../../include/openenclave/bits/time.h"
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

void HandleNanosleep(uint64_t argIn)
{
    oe_nanosleep_args_t* args = (oe_nanosleep_args_t*)argIn;

    if (!args)
        return;

    args->ret = nanosleep(args->req, args->rem);
}
