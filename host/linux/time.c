// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.
#if defined(__linux__)
#include "../ocalls.h"
#include "../../include/openenclave/bits/calls.h"


void HandleStrftime(uint64_t argIn)
{
    OE_StrftimeArgs* args = (OE_StrftimeArgs*)argIn;

    if (!args)
        return;

    args->ret = strftime(args->str, sizeof(args->str), args->format, &args->tm);

}


void HandleGettimeofday(uint64_t argIn)
{
    OE_GettimeofdayArgs* args = (OE_GettimeofdayArgs*)argIn;

    if (!args)
        return;

    args->ret = gettimeofday(args->tv, args->tz);

}

void HandleClockgettime(uint64_t argIn)
{
    OE_ClockgettimeArgs* args = (OE_ClockgettimeArgs*)argIn;

    if (!args)
        return;

    printf("\n\n\n Linux clock_gettime function called ....\n");
    args->ret = clock_gettime(args->clk_id, args->tp);
    printf("\n LINUX  Time in seconds %ld", args->tp->tv_sec);
    printf("\n LINUX  Time in neno seconds %ld", args->tp->tv_nsec);
}

void HandleNanosleep(uint64_t argIn)
{
    OE_NanosleepArgs* args = (OE_NanosleepArgs*)argIn;

    if (!args)
        return;

    args->ret = nanosleep(args->req, args->rem);

}
#endif//__linux__
