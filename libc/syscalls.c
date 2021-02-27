// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#define __OE_NEED_TIME_CALLS
#define _GNU_SOURCE

#include <errno.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/enclave.h>
#include <openenclave/internal/calls.h>
#include <openenclave/internal/syscall/declarations.h>
#include <openenclave/internal/syscall/hook.h>
#include <openenclave/internal/syscall/sys/stat.h>
#include <openenclave/internal/syscall/sys/syscall.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/time.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <time.h>

static oe_syscall_hook_t _hook;
static oe_spinlock_t _lock;

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_USEC = 1000UL;
static const uint64_t _MSEC_TO_NSEC = 1000000UL;

OE_DEFINE_SYSCALL6(SYS_mmap)
{
    /* Always fail */
    return EPERM;
}

OE_DEFINE_SYSCALL2(SYS_munmap)
{
    /* Always fail */
    return EPERM;
}

weak OE_DEFINE_SYSCALL2(SYS_clock_gettime)
{
    clockid_t clock_id = (clockid_t)arg1;
    struct timespec* tp = (struct timespec*)arg2;
    int ret = -1;
    uint64_t msec;

    if (!tp)
        goto done;

    if (clock_id != CLOCK_REALTIME)
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

OE_DEFINE_SYSCALL2(SYS_gettimeofday)
{
    struct timeval* tv = (struct timeval*)arg1;
    void* tz = (void*)arg2;
    int ret = -1;
    uint64_t msec;

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

static void _stat_to_oe_stat(struct stat* stat, struct oe_stat_t* oe_stat)
{
    oe_stat->st_dev = stat->st_dev;
    oe_stat->st_ino = stat->st_ino;
    oe_stat->st_nlink = stat->st_nlink;
    oe_stat->st_mode = stat->st_mode;
    oe_stat->st_uid = stat->st_uid;
    oe_stat->st_gid = stat->st_gid;
    oe_stat->st_rdev = stat->st_rdev;
    oe_stat->st_size = stat->st_size;
    oe_stat->st_blksize = stat->st_blksize;
    oe_stat->st_blocks = stat->st_blocks;
    oe_stat->st_atim.tv_sec = stat->st_atim.tv_sec;
    oe_stat->st_atim.tv_nsec = stat->st_atim.tv_nsec;
    oe_stat->st_ctim.tv_sec = stat->st_ctim.tv_sec;
    oe_stat->st_ctim.tv_nsec = stat->st_ctim.tv_nsec;
    oe_stat->st_mtim.tv_sec = stat->st_mtim.tv_sec;
    oe_stat->st_mtim.tv_nsec = stat->st_mtim.tv_nsec;
}

static void _oe_stat_to_stat(struct oe_stat_t* oe_stat, struct stat* stat)
{
    stat->st_dev = oe_stat->st_dev;
    stat->st_ino = oe_stat->st_ino;
    stat->st_nlink = oe_stat->st_nlink;
    stat->st_mode = oe_stat->st_mode;
    stat->st_uid = oe_stat->st_uid;
    stat->st_gid = oe_stat->st_gid;
    stat->st_rdev = oe_stat->st_rdev;
    stat->st_size = oe_stat->st_size;
    stat->st_blksize = oe_stat->st_blksize;
    stat->st_blocks = oe_stat->st_blocks;
    stat->st_atim.tv_sec = oe_stat->st_atim.tv_sec;
    stat->st_atim.tv_nsec = oe_stat->st_atim.tv_nsec;
    stat->st_ctim.tv_sec = oe_stat->st_ctim.tv_sec;
    stat->st_ctim.tv_nsec = oe_stat->st_ctim.tv_nsec;
    stat->st_mtim.tv_sec = oe_stat->st_mtim.tv_sec;
    stat->st_mtim.tv_nsec = oe_stat->st_mtim.tv_nsec;
}

static long _dispatch_oe_syscall(
    long n,
    long x1,
    long x2,
    long x3,
    long x4,
    long x5,
    long x6)
{
    long ret;

    switch (n)
    {
#if defined(SYS_stat)
        case SYS_stat:
        {
            struct stat* stat = (struct stat*)x2;
            struct oe_stat_t oe_stat;

            _stat_to_oe_stat(stat, &oe_stat);
            x2 = (long)&oe_stat;
            ret = oe_syscall(OE_SYS_stat, x1, x2, x3, x4, x5, x6);
            _oe_stat_to_stat(&oe_stat, stat);

            break;
        }
#endif
        case SYS_newfstatat:
        {
            struct stat* stat = (struct stat*)x3;
            struct oe_stat_t oe_stat;

            _stat_to_oe_stat(stat, &oe_stat);
            x3 = (long)&oe_stat;
            ret = oe_syscall(OE_SYS_newfstatat, x1, x2, x3, x4, x5, x6);
            _oe_stat_to_stat(&oe_stat, stat);

            break;
        }
        default:
        {
            ret = oe_syscall(n, x1, x2, x3, x4, x5, x6);
            break;
        }
    }

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

    /* Handle syscall internally if possible. */
    switch (n)
    {
        OE_SYSCALL_DISPATCH(SYS_clock_gettime, x1, x2);
        OE_SYSCALL_DISPATCH(SYS_gettimeofday, x1, x2);
        OE_SYSCALL_DISPATCH(SYS_mmap, x1, x2, x3, x4, x5, x6);

        default:
            /* Drop through and let the code below handle the syscall. */
            break;
    }

    /* Let liboesyscall handle select system calls. */
    {
        long ret;

        errno = 0;

        ret = _dispatch_oe_syscall(n, x1, x2, x3, x4, x5, x6);

        if (!(ret == -1 && errno == ENOSYS))
        {
            return ret;
        }
    }

    /* All other MUSL-initiated syscalls are aborted. */
    fprintf(stderr, "error: unhandled syscall: n=%lu\n", n);
    abort();
}

// Declared as weak alias to allow enclave authors to implement unsupported
// syscalls selectively without increasing TCB.
long syscall_impl(long number, ...)
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

OE_WEAK_ALIAS(syscall_impl, syscall);

long __syscall_ret(unsigned long r)
{
    /* Override MUSL __syscall_ret (maps certain return values to errnos). */
    return r;
}

void oe_register_syscall_hook(oe_syscall_hook_t hook)
{
    oe_spin_lock(&_lock);
    _hook = hook;
    oe_spin_unlock(&_lock);
}
