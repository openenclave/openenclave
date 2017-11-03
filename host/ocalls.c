#include <stdio.h>
#include <time.h>
#include <sys/time.h>
#include <stdlib.h>
#include <assert.h>
#include <linux/futex.h>
#include <unistd.h>
#include <sys/syscall.h>

#include <openenclave/host.h>
#define __OE_NEED_TIME_CALLS
#include <openenclave/bits/calls.h>
#include <openenclave/bits/utils.h>
#include "enclave.h"
#include "ocalls.h"

void HandleMalloc(uint64_t argIn, uint64_t* argOut)
{
    if (argOut)
        *argOut = (uint64_t)malloc(argIn);
}

void HandleFree(uint64_t arg)
{
    free((void*)arg);
}

void HandlePuts(uint64_t argIn)
{
    const char* str = (const char*)argIn;

    if (str)
        puts(str);
}

void HandlePrint(uint64_t argIn)
{
    OE_PrintArgs* args = (OE_PrintArgs*)argIn;

    if (args)
    {
        if (args->device == 0)
        {
            fprintf(stdout, "%s", args->str);
            fflush(stdout);
        }
        else if (args->device == 1)
        {
            fprintf(stderr, "%s", args->str);
            fflush(stderr);
        }
    }
}

void HandlePutchar(uint64_t argIn)
{
    int c = (int)argIn;
    putchar(c);
}

void HandleThreadWait(uint64_t argIn)
{
    const uint64_t tcs = argIn;
    uint32_t* event;

    event = GetEnclaveEvent(tcs);
    assert(event);

    if (__sync_fetch_and_add(&event, -1) == 0)
        syscall(__NR_futex, &event, FUTEX_WAIT, -1, NULL, NULL, 0);
}

void HandleThreadWake(uint64_t argIn)
{
    const uint64_t tcs = argIn;
    uint32_t* event;

    event = GetEnclaveEvent(tcs);
    assert(event);

    if (__sync_fetch_and_add(&event, 1) != 0)
        syscall(__NR_futex, &event, FUTEX_WAKE, 1, NULL, NULL, 0);
}

void HandleThreadWakeWait(uint64_t argIn)
{
    OE_ThreadWakeWaitArgs* args = (OE_ThreadWakeWaitArgs*)argIn;

    if (!args)
        return;

    HandleThreadWake((uint64_t)args->waiter_tcs);
    HandleThreadWait((uint64_t)args->self_tcs);
}

void HandleInitQuote(uint64_t argIn)
{
    OE_InitQuoteArgs* args = (OE_InitQuoteArgs*)argIn;

    if (!args)
        return;

    args->result = SGX_InitQuote(&args->targetInfo, &args->epidGroupID);
}

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

    args->ret = clock_gettime(args->clk_id, args->tp);
}

void HandleNanosleep(uint64_t argIn)
{
    OE_NanosleepArgs* args = (OE_NanosleepArgs*)argIn;

    if (!args)
        return;

    args->ret = nanosleep(args->req, args->rem);
}
