// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/types.h>
#include <openenclave/internal/time.h>
#include <stdio.h>
#include <windows.h>

void HandleStrftime(uint64_t argIn)
{
    OE_UNUSED(argIn);
    abort();
}

void HandleGettimeofday(uint64_t argIn)
{
    OE_UNUSED(argIn);
    abort();
}

void HandleClockgettime(uint64_t argIn)
{
    oe_clock_gettime_args_t* args = (oe_clock_gettime_args_t*)argIn;
    if (!args)
        return;

    // Ticks from Windows epoch at 1 Jan 1601 to POSIX epoch at 1 Jan 1970
    // This is derived from SystemTimeToFileTime of:
    // const SYSTEMTIME POSIX_EPOCH = { 1970, 1, 4, 1 };
    static const uint64_t POSIX_TO_WINDOWS_EPOCH_TICKS = 116444736000000000;

    // Windows ticks once every 100 nanoseconds.
    const uint32_t WINDOWS_NS_PER_TICK = 100;
    const uint32_t WINDOWS_SEC_PER_TICK = 1E9 / WINDOWS_NS_PER_TICK;

    // Get the current Windows System time
    FILETIME currentTime;
    GetSystemTimeAsFileTime(&currentTime);

    // Convert Windows time in ticks to POSIX time in ticks
    ULARGE_INTEGER currentTimePosix;
    currentTimePosix.HighPart = currentTime.dwHighDateTime;
    currentTimePosix.LowPart = currentTime.dwLowDateTime;
    currentTimePosix.QuadPart -= POSIX_TO_WINDOWS_EPOCH_TICKS;

    // Convert POSIX time in ticks to seconds.nanoseconds
    UINT64 sec = currentTimePosix.QuadPart / WINDOWS_SEC_PER_TICK;
    UINT64 nsec = (currentTimePosix.QuadPart % WINDOWS_SEC_PER_TICK) *
                  WINDOWS_NS_PER_TICK;
    if (sec > OE_MAX_UINT32 || nsec > OE_MAX_UINT32)
    {
        // Unexpected, current time exceeds POSIX timespec range
        args->tp->tv_sec = (time_t)-1;
        args->tp->tv_nsec = -1;
        args->ret = -1;
    }
    else
    {
        args->tp->tv_sec = (time_t)sec;
        args->tp->tv_nsec = (long)nsec;
        args->ret = 0;
    }
}

void oe_handle_sleep_ocall(uint64_t argIn)
{
    OE_UNUSED(argIn);
    abort();
}
