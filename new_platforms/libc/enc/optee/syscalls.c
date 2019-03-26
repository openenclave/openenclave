// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <stdarg.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/uio.h>

static long _syscall_nanosleep(long n, long x1, long x2)
{
    (void)(n);
    (void)(x1);
    (void)(x2);

    return EFAULT;
}

static long _syscall_gettimeofday(long n, long x1, long x2)
{
    (void)(n);
    (void)(x1);
    (void)(x2);

    return EPERM;
}

static long _syscall_clock_gettime(long n, long x1, long x2)
{
    (void)(n);
    (void)(x1);
    (void)(x2);

    return EPERM;
}

static long
_syscall_writev(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    const struct iovec* iov = (const struct iovec*)x2;
    unsigned long iovcnt = (unsigned long)x3;
    long ret = 0;

    (void)(n);
    (void)(x1);
    (void)(x4);
    (void)(x5);
    (void)(x6);

    for (unsigned long i = 0; i < iovcnt; i++)
    {
        ret += iov[i].iov_len;
    }

    return ret;
}

static long
_syscall_ioctl(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    (void)(n);
    (void)(x1);
    (void)(x2);
    (void)(x3);
    (void)(x4);
    (void)(x5);
    (void)(x6);

    return 0;
}

static long
_syscall_open(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    (void)(n);
    (void)(x1);
    (void)(x2);
    (void)(x3);
    (void)(x4);
    (void)(x5);
    (void)(x6);

    return -1;
}

static long _syscall_close(long n, ...)
{
    /* required by mbedtls */
    (void)(n);
    return 0;
}

static long _syscall_mmap(long n, ...)
{
    /* Always fail */
    (void)(n);
    return EPERM;
}

static long _syscall_readv(long n, ...)
{
    /* required by mbedtls */

    /* return zero-bytes read */
    (void)(n);
    return 0;
}

/* Intercept __syscalls() from MUSL */
long __syscall(long n, long x1, long x2, long x3, long x4, long x5, long x6)
{
    switch (n)
    {
        case 35:
            return _syscall_nanosleep(n, x1, x2);
        case 96:
            return _syscall_gettimeofday(n, x1, x2);
        case 228:
            return _syscall_clock_gettime(n, x1, x2);
        case 20:
            return _syscall_writev(n, x1, x2, x3, x4, x5, x6);
        case 16:
            return _syscall_ioctl(n, x1, x2, x3, x4, x5, x6);
        case 2:
            return _syscall_open(n, x1, x2, x3, x4, x5, x6);
        case 3:
            return _syscall_close(n, x1, x2, x3, x4, x5, x6);
        case 9:
            return _syscall_mmap(n, x1, x2, x3, x4, x5, x6);
        case 19:
            return _syscall_readv(n, x1, x2, x3, x4, x5, x6);
        default:
        {
            return EPERM;
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
