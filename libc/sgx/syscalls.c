// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#define __OE_NEED_TIME_CALLS
#define _GNU_SOURCE
#include <assert.h>
#include <errno.h>
#include <fcntl.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/syscall.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <time.h>
#include <unistd.h>

static oe_syscall_hook_t _hook;
static oe_spinlock_t _lock;

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_USEC = 1000UL;
static const uint64_t _MSEC_TO_NSEC = 1000000UL;

static long
_syscall_open(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    const char* filename = (const char*)x1;
    int flags = (int)x2;
    int mode = (int)x3;

    OE_UNUSED(n);
    OE_UNUSED(x4);
    OE_UNUSED(x5);
    OE_UNUSED(x6);
    OE_UNUSED(filename);
    OE_UNUSED(flags);
    OE_UNUSED(mode);

    if (flags == O_WRONLY)
        return STDOUT_FILENO;

    return -1;
}

static long _syscall_close(long n, ...)
{
    /* required by mbedtls */
    OE_UNUSED(n);
    return 0;
}

static long _syscall_mmap(long n, ...)
{
    /* Always fail */
    OE_UNUSED(n);
    return EPERM;
}

static long _syscall_readv(long n, ...)
{
    /* required by mbedtls */

    /* return zero-bytes read */
    OE_UNUSED(n);
    return 0;
}

static long
_syscall_ioctl(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    int fd = (int)x1;

    OE_UNUSED(n);
    OE_UNUSED(x2);
    OE_UNUSED(x3);
    OE_UNUSED(x4);
    OE_UNUSED(x5);
    OE_UNUSED(x6);

    /* only allow ioctl() on these descriptors */
    if (fd != STDIN_FILENO && fd != STDOUT_FILENO && fd != STDERR_FILENO)
        abort();

    return 0;
}

static long
_syscall_writev(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    int fd = (int)x1;
    const struct iovec* iov = (const struct iovec*)x2;
    unsigned long iovcnt = (unsigned long)x3;
    long ret = 0;
    int device;

    OE_UNUSED(n);
    OE_UNUSED(x4);
    OE_UNUSED(x5);
    OE_UNUSED(x6);

    /* Allow writing only to stdout and stderr */
    switch (fd)
    {
        case STDOUT_FILENO:
        {
            device = 0;
            break;
        }
        case STDERR_FILENO:
        {
            device = 1;
            break;
        }
        default:
        {
            abort();
        }
    }

    for (unsigned long i = 0; i < iovcnt; i++)
    {
        oe_host_write(device, iov[i].iov_base, iov[i].iov_len);
        ret += iov[i].iov_len;
    }

    return ret;
}

static long _syscall_clock_gettime(long n, long x1, long x2)
{
    clockid_t clk_id = (clockid_t)x1;
    struct timespec* tp = (struct timespec*)x2;
    int ret = -1;
    uint64_t msec;

    OE_UNUSED(n);

    if (!tp)
        goto done;

    if (clk_id != CLOCK_REALTIME)
    {
        /* Only supporting CLOCK_REALTIME */
        oe_assert("clock_gettime(): panic" == NULL);
        goto done;
    }

    if ((msec = oe_get_time()) == (uint64_t)-1)
        goto done;

    tp->tv_sec = msec / _SEC_TO_MSEC;
    tp->tv_nsec = (msec % _SEC_TO_MSEC) * _MSEC_TO_NSEC;

    ret = 0;

done:

    return ret;
}

static long _syscall_gettimeofday(long n, long x1, long x2)
{
    struct timeval* tv = (struct timeval*)x1;
    void* tz = (void*)x2;
    int ret = -1;
    uint64_t msec;

    OE_UNUSED(n);

    if (tv)
        memset(tv, 0, sizeof(struct timeval));

    if (tz)
        memset(tz, 0, sizeof(struct timezone));

    if (!tv)
        goto done;

    if ((msec = oe_get_time()) == (uint64_t)-1)
        goto done;

    tv->tv_sec = msec / _SEC_TO_MSEC;
    tv->tv_usec = msec % _MSEC_TO_USEC;

    ret = 0;

done:
    return ret;
}

static long _syscall_nanosleep(long n, long x1, long x2)
{
    const struct timespec* req = (struct timespec*)x1;
    struct timespec* rem = (struct timespec*)x2;
    size_t ret = -1;
    uint64_t milliseconds = 0;

    OE_UNUSED(n);

    if (rem)
        memset(rem, 0, sizeof(*rem));

    if (!req)
        goto done;

    /* Convert timespec to milliseconds */
    milliseconds += req->tv_sec * 1000UL;
    milliseconds += req->tv_nsec / 1000000UL;

    /* Perform OCALL */
    ret = oe_sleep(milliseconds);

done:

    return ret;
}

/* Intercept __syscalls() from MUSL */
long __syscall(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    oe_spin_lock(&_lock);
    oe_syscall_hook_t hook = _hook;
    oe_spin_unlock(&_lock);

    /* Invoke the syscall hook if any */
    if (hook)
    {
        long ret = -1;

        if (hook(n, x1, x2, x3, x4, x5, x6, &ret) == OE_OK)
        {
            /* The hook handled the syscall */
            return ret;
        }

        /* The hook ignored the syscall so fall through */
    }

    switch (n)
    {
        case SYS_nanosleep:
            return _syscall_nanosleep(n, x1, x2);
        case SYS_gettimeofday:
            return _syscall_gettimeofday(n, x1, x2);
        case SYS_clock_gettime:
            return _syscall_clock_gettime(n, x1, x2);
        case SYS_writev:
            return _syscall_writev(n, x1, x2, x3, x4, x5, x6);
        case SYS_ioctl:
            return _syscall_ioctl(n, x1, x2, x3, x4, x5, x6);
        case SYS_open:
            return _syscall_open(n, x1, x2, x3, x4, x5, x6);
        case SYS_close:
            return _syscall_close(n, x1, x2, x3, x4, x5, x6);
        case SYS_mmap:
            return _syscall_mmap(n, x1, x2, x3, x4, x5, x6);
        case SYS_readv:
            return _syscall_readv(n, x1, x2, x3, x4, x5, x6);
        default:
        {
            /* All other MUSL-initiated syscalls are aborted. */
            fprintf(stderr, "error: __syscall(): n=%lu\n", n);
            abort();
            return 0;
        }
    }

    return 0;
}

/* Intercept __syscalls_cp() from MUSL */
long __syscall_cp(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    return __syscall(n, x1, x2, x3, x4, x5, x6);
}

long syscall(long number, ...)
{
    va_list ap;

    va_start(ap, number);
    long x1 = va_arg(ap, long);
    long x2 = va_arg(ap, long);
    long x3 = va_arg(ap, long);
    long x4 = va_arg(ap, long);
    long x5 = va_arg(ap, long);
    long x6 = va_arg(ap, long);
    long ret = __syscall(number, x1, x2, x3, x4, x5, x6);
    va_end(ap);

    return ret;
}

void oe_register_syscall_hook(oe_syscall_hook_t hook)
{
    oe_spin_lock(&_lock);
    _hook = hook;
    oe_spin_unlock(&_lock);
}
