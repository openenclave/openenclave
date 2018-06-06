// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "../ocalls.h"
#include "../../include/openenclave/bits/calls.h"


void HandleStrftime(uint64_t argIn)
{
    OE_StrftimeArgs* args = (OE_StrftimeArgs*)argIn;

    if (!args)
        return;
#if defined __OE_NEED_TIME_CALLS
    args->ret = strftime(args->str, sizeof(args->str), args->format, &args->tm);
#endif
}


void HandleGettimeofday(uint64_t argIn)
{
    OE_GettimeofdayArgs* args = (OE_GettimeofdayArgs*)argIn;

    if (!args)
        return;
#if defined __OE_NEED_TIME_CALLS
    args->ret = gettimeofday(args->tv, args->tz);
#endif
}

void HandleClockgettime(uint64_t argIn)
{
    OE_ClockgettimeArgs* args = (OE_ClockgettimeArgs*)argIn;

    if (!args)
        return;
#if defined __OE_NEED_TIME_CALLS
    printf("\n\n\n Linux clock_gettime function called ....\n");
    args->ret = clock_gettime(args->clk_id, args->tp);
#endif
}

void HandleNanosleep(uint64_t argIn)
{
    OE_NanosleepArgs* args = (OE_NanosleepArgs*)argIn;

    if (!args)
        return;
#if defined __OE_NEED_TIME_CALLS
    args->ret = nanosleep(args->req, args->rem);
#endif
}
