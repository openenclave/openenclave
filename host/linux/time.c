// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#define _ADD_OE_TIME_CALLS
#include "../../include/openenclave/bits/calls.h"
#include "../ocalls.h"

void HandleStrftime(uint64_t argIn)
{
#if defined(_ADD_OE_TIME_CALLS)
    OE_StrftimeArgs* args = (OE_StrftimeArgs*)argIn;

    if (!args)
        return;

    args->ret = strftime(args->str, sizeof(args->str), args->format, &args->tm);
#endif
}

void HandleGettimeofday(uint64_t argIn)
{
#if defined(_ADD_OE_TIME_CALLS)
    OE_GettimeofdayArgs* args = (OE_GettimeofdayArgs*)argIn;

    if (!args)
        return;

    args->ret = gettimeofday(args->tv, args->tz);
#endif
}

void HandleClockgettime(uint64_t argIn)
{
#if defined(_ADD_OE_TIME_CALLS)
    OE_ClockgettimeArgs* args = (OE_ClockgettimeArgs*)argIn;

    if (!args)
        return;

    args->ret = clock_gettime(args->clk_id, args->tp);
#endif
}

void HandleNanosleep(uint64_t argIn)
{
#if defined(_ADD_OE_TIME_CALLS)
    OE_NanosleepArgs* args = (OE_NanosleepArgs*)argIn;

    if (!args)
        return;

    args->ret = nanosleep(args->req, args->rem);
#endif
}
