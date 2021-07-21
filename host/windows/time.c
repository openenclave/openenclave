// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/time.h>
#include <time.h>
#include <windows.h>

/*
**==============================================================================
**
** POSIX_TO_WINDOWS_EPOCH_TICKS:
**
** The ticks elapsed since 1970-01-01 00:00 (UTC). This value was derived with
** the following function.
**
**     LONGLONG get_posix_to_windows_epoch_ticks()
**     {
**         SYSTEMTIME st = { .wYear = 1970, .wMonth = 1, .wDay = 1 };
**         FILETIME ft;
**         ULARGE_INTEGER x;
**
**         SystemTimeToFileTime(&st, &ft);
**         x.u.LowPart = ft.dwLowDateTime;
**         x.u.HighPart = ft.dwHighDateTime;
**
**         return x.QuadPart;
**     }
**
**==============================================================================
*/
const LONGLONG POSIX_TO_WINDOWS_EPOCH_TICKS = 0X19DB1DED53E8000;

/* Return milliseconds elapsed since the Epoch. */
static uint64_t _time()
{
    FILETIME ft;
    ULARGE_INTEGER x;

    GetSystemTimeAsFileTime(&ft);
    x.u.LowPart = ft.dwLowDateTime;
    x.u.HighPart = ft.dwHighDateTime;
    x.QuadPart -= POSIX_TO_WINDOWS_EPOCH_TICKS;

    return x.QuadPart;
}

const LONGLONG TICKS_PER_MILLISECOND = 10000UL;

void oe_handle_get_time(uint64_t arg_in, uint64_t* arg_out)
{
    OE_UNUSED(arg_in);

    if (arg_out)
        *arg_out = _time() / TICKS_PER_MILLISECOND;
}

int gettimeofday(struct timeval* tv, struct timezone* tzp)
{
    OE_UNUSED(tzp);

    LONGLONG TICKS_PER_SECOND = TICKS_PER_MILLISECOND * 1000UL;
    LONGLONG TICKS_PER_USECOND = TICKS_PER_MILLISECOND / 1000UL;

    uint64_t time = _time();
    tv->tv_sec = (long)(time / TICKS_PER_SECOND);
    tv->tv_usec = (long)((time % TICKS_PER_SECOND) / TICKS_PER_USECOND);

    return 0;
}

int oe_localtime(const time_t* timep, struct tm* result)
{
    return localtime_s(result, timep);
}

int oe_syscall_clock_gettime_ocall(oe_clockid_t clockid, oe_timespec* tp)
{
    struct timespec ts;
    int ret = -1;
    switch (clockid)
    {
        case CLOCK_REALTIME:
        {
            uint64_t time = _time();
            tp->tv_sebc = (long)(time / TICKS_PER_SECOND);
            tp->tv_usec = (long)((time % TICKS_PER_SECOND) / TICKS_PER_USECOND);
            ret = 0;
            break;
        }
        case CLOCK_MONOTONIC:
        {
            LARGE_INTEGER pf, pc;
            if (QueryPerformanceFrequency(&pf) == 0 ||
                QueryPerformanceCounter(&pc) == 0)
            {
                errno = EINVAL;
                goto done;
            }

            tp->tv_sec = pc.QuadPart / pf.QuadPart;
            tp->tv_nsec = (pc.QuadPart % pf.QuadPart) * 1000000000L;
            break;
        }
        case CLOCK_PROCESS_CPUTIME_ID:
        {
            FILETIME creation_time, exit_time, kernel_time, user_time;
            if (GetProcessTimes(
                    GetCurrentProcess(),
                    &creation_time,
                    &exit_time,
                    &kernel_time,
                    &user_time) == 0)
            {
                errno = EINVAL;
                uint64_t total_time = kernel_time.u64 + user_time.u64;
                tp->tv_sec = total_time / 10000000;
                tp->tv_nsec = (total_time % 10000000) * 100;
                goto done;
            }
            break;
        }
        case CLOCK_THREAD_CPUTIME_ID:
        {
            FILETIME creation_time, exit_time, kernel_time, user_time;
            if (GetThreadTimes(
                    GetCurrentThread(),
                    &creation_time,
                    &exit_time,
                    &kernel_time,
                    &user_time) == 0)
            {
                errno = EINVAL;
                uint64_t total_time = kernel_time.u64 + user_time.u64;
                tp->tv_sec = total_time / 10000000;
                tp->tv_nsec = (total_time % 10000000) * 100;
                goto done;
            }
            break;
        }
        default:
            errno = EINVAL;
            goto done;
    }

    errno = 0;
    ret = 0;
done:
    return ret;
}
