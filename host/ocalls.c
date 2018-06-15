// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#if defined(__linux__)
#define __OE_NEED_TIME_CALLS
#endif

#include <assert.h>
#include <stdio.h>

#if defined(__linux__)
#include <linux/futex.h>
#include <stdlib.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>
#elif defined(_WIN32)
#include <Windows.h>
#endif

#include <openenclave/host.h>

#include <openenclave/internal/calls.h>
#include <openenclave/internal/utils.h>
#include "enclave.h"
#include "ocalls.h"
#include "quote.h"

void HandleMalloc(uint64_t arg_in, uint64_t* arg_out)
{
    if (arg_out)
        *arg_out = (uint64_t)malloc(arg_in);
}

void HandleRealloc(uint64_t arg_in, uint64_t* arg_out)
{
    oe_realloc_args_t* args = (oe_realloc_args_t*)arg_in;

    if (args)
    {
        if (arg_out)
            *arg_out = (uint64_t)realloc(args->ptr, args->size);
    }
}

void HandleFree(uint64_t arg)
{
    free((void*)arg);
}

void HandlePuts(uint64_t arg_in)
{
    const char* str = (const char*)arg_in;

    if (str)
        puts(str);
}

void HandlePrint(uint64_t arg_in)
{
    oe_print_args_t* args = (oe_print_args_t*)arg_in;

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

void HandlePutchar(uint64_t arg_in)
{
    int c = (int)arg_in;
    putchar(c);
}

void HandleThreadWait(oe_enclave_t* enclave, uint64_t arg_in)
{
    const uint64_t tcs = arg_in;
    EnclaveEvent* event = GetEnclaveEvent(enclave, tcs);
    assert(event);

#if defined(__linux__)

    if (__sync_fetch_and_add(&event->value, -1) == 0)
    {
        do
        {
            syscall(
                __NR_futex,
                &event->value,
                FUTEX_WAIT_PRIVATE,
                -1,
                NULL,
                NULL,
                0);
            // If event->value is still -1, then this is a spurious-wake.
            // Spurious-wakes are ignored by going back to FUTEX_WAIT.
            // Since FUTEX_WAIT uses atomic instructions to load event->value,
            // it is safe to use a non-atomic operation here.
        } while (event->value == -1);
    }

#elif defined(_WIN32)

    WaitForSingleObject(event->handle, INFINITE);

#endif
}

void HandleThreadWake(oe_enclave_t* enclave, uint64_t arg_in)
{
    const uint64_t tcs = arg_in;
    EnclaveEvent* event = GetEnclaveEvent(enclave, tcs);
    assert(event);

#if defined(__linux__)

    if (__sync_fetch_and_add(&event->value, 1) != 0)
        syscall(
            __NR_futex, &event->value, FUTEX_WAKE_PRIVATE, 1, NULL, NULL, 0);

#elif defined(_WIN32)

    SetEvent(event->handle);

#endif
}

void HandleThreadWakeWait(oe_enclave_t* enclave, uint64_t arg_in)
{
    oe_thread_wake_wait_args_t* args = (oe_thread_wake_wait_args_t*)arg_in;

    if (!args)
        return;

#if defined(__linux__)

    HandleThreadWake(enclave, (uint64_t)args->waiter_tcs);
    HandleThreadWait(enclave, (uint64_t)args->self_tcs);

#elif defined(_WIN32)

    HandleThreadWake(enclave, (uint64_t)args->waiter_tcs);
    HandleThreadWait(enclave, (uint64_t)args->self_tcs);

#endif
}

void HandleGetQuote(uint64_t arg_in)
{
    oe_get_quote_args_t* args = (oe_get_quote_args_t*)arg_in;
    if (!args)
        return;

    args->result =
        sgx_get_quote(&args->sgx_report, args->quote, &args->quote_size);
}

void HandleGetQETargetInfo(uint64_t arg_in)
{
    oe_get_qetarget_info_args_t* args = (oe_get_qetarget_info_args_t*)arg_in;
    if (!args)
        return;

    args->result = sgx_get_qetarget_info(&args->target_info);
}

#if defined(__OE_NEED_TIME_CALLS)
void HandleStrftime(uint64_t arg_in)
{
    oe_strftime_args_t* args = (oe_strftime_args_t*)arg_in;

    if (!args)
        return;

    args->ret = strftime(args->str, sizeof(args->str), args->format, &args->tm);
}
#endif

#if defined(__OE_NEED_TIME_CALLS)
void HandleGettimeofday(uint64_t arg_in)
{
    oe_gettimeofday_args_t* args = (oe_gettimeofday_args_t*)arg_in;

    if (!args)
        return;

    args->ret = gettimeofday(args->tv, args->tz);
}
#endif

#if defined(__OE_NEED_TIME_CALLS)
void HandleClockgettime(uint64_t arg_in)
{
    oe_clock_gettime_args_t* args = (oe_clock_gettime_args_t*)arg_in;

    if (!args)
        return;

    args->ret = clock_gettime(args->clk_id, args->tp);
}
#endif

#if defined(__OE_NEED_TIME_CALLS)
void HandleNanosleep(uint64_t arg_in)
{
    oe_nanosleep_args_t* args = (oe_nanosleep_args_t*)arg_in;

    if (!args)
        return;

    args->ret = nanosleep(args->req, args->rem);
}
#endif
