// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/syscall/sys/syscall.h>

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <wchar.h>

#include <sys/stat.h>
#include <sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>

#include "test_t.h"

int pthread_condattr_init(void* ca)
{
    OE_UNUSED(ca);
    return -1;
}

int pthread_condattr_setclock(void* ca, long clk)
{
    OE_UNUSED(ca);
    OE_UNUSED(clk);
    return -1;
}

int sem_init(void* lock, int a, int b)
{
    OE_UNUSED(lock);
    OE_UNUSED(a);
    OE_UNUSED(b);
    return 0;
}

ssize_t readlink(const char* __restrict path, char* __restrict cbuf, size_t len)
{
    OE_UNUSED(path);
    OE_UNUSED(cbuf);
    OE_UNUSED(len);
    errno = EINVAL;
    return -1;
}

int getrandom(void* buf, size_t buflen, unsigned int flags)
{
    OE_UNUSED(flags);
    oe_random(buf, buflen);
    return 0;
}

int sem_wait(void* sem)
{
    OE_UNUSED(sem);
    return 0;
}

int sem_post(void* sem)
{
    OE_UNUSED(sem);
    return 0;
}

int issetugid()
{
    return 0;
}

int isatty(int fd)
{
    OE_UNUSED(fd);
    return 1;
}

char* oe_realpath(const char* path, char* resolved_path);

char* realpath(const char* path, char* resolved_path)
{
    return oe_realpath(path, resolved_path);
}

// Lib event tries opening pipes on sockets.
// We can either compile libevent without pipes
// or just fail the pipe calls so that livevent doesn't
// use them.
int pipe(int fd[2])
{
    OE_UNUSED(fd);
    return -1;
}

int pipe2(int fd[2], int m)
{
    OE_UNUSED(fd);
    OE_UNUSED(m);
    return -1;
}

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_NSEC = 1000000UL;

uint64_t oe_get_time(void);

OE_DEFINE_SYSCALL2(SYS_clock_gettime)
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
        // oe_assert("clock_gettime(): panic" == NULL);
        // goto done;
    }

    if ((msec = oe_get_time()) == (uint64_t)-1)
        goto done;

    tp->tv_sec = msec / _SEC_TO_MSEC;
    tp->tv_nsec = (msec % _SEC_TO_MSEC) * _MSEC_TO_NSEC;

    ret = 0;

done:

    return ret;
}

struct sockaddr;
typedef size_t socklen_t;
int accept(int sockfd, struct sockaddr* addr, socklen_t* addrlen);
int accept4(int sockfd, struct sockaddr* addr, socklen_t* addrlen, int flags)
{
    OE_UNUSED(flags);
    return accept(sockfd, addr, addrlen);
}

int lstat(const char* pathname, struct stat* statbuf)
{
    // Symbolic links are not expected. Therefore OK to forward to stat.
    return stat(pathname, statbuf);
}

long syscall(long number, ...)
{
    va_list ap;
    va_start(ap, number);
    long x1 = va_arg(ap, long);
    va_end(ap);

    switch (number)
    {
        case SYS_close:
            return close(x1);

        case SYS_statx:
        // SYS_statx is called by libuv; but it can deal if not implemented.
        default:
            // printf("Unimplemented syscall called: %d\n", number);
            errno = ENOSYS;
    }

    return -1;
}

#include <errno.h>
#include <limits.h>
#include <unistd.h>

long fpathconf(int fd, int name)
{
    OE_UNUSED(fd);
    static const short values[] = {[_PC_LINK_MAX] = _POSIX_LINK_MAX,
                                   [_PC_MAX_CANON] = _POSIX_MAX_CANON,
                                   [_PC_MAX_INPUT] = _POSIX_MAX_INPUT,
                                   [_PC_NAME_MAX] = NAME_MAX,
                                   [_PC_PATH_MAX] = PATH_MAX,
                                   [_PC_PIPE_BUF] = PIPE_BUF,
                                   [_PC_CHOWN_RESTRICTED] = 1,
                                   [_PC_NO_TRUNC] = 1,
                                   [_PC_VDISABLE] = 0,
                                   [_PC_SYNC_IO] = 1,
                                   [_PC_ASYNC_IO] = -1,
                                   [_PC_PRIO_IO] = -1,
                                   [_PC_SOCK_MAXBUF] = -1,
                                   [_PC_FILESIZEBITS] = FILESIZEBITS,
                                   [_PC_REC_INCR_XFER_SIZE] = 4096,
                                   [_PC_REC_MAX_XFER_SIZE] = 4096,
                                   [_PC_REC_MIN_XFER_SIZE] = 4096,
                                   [_PC_REC_XFER_ALIGN] = 4096,
                                   [_PC_ALLOC_SIZE_MIN] = 4096,
                                   [_PC_SYMLINK_MAX] = -1,
                                   [_PC_2_SYMLINKS] = 1};
    if (name >= (int)(sizeof(values) / sizeof(values[0])))
    {
        errno = EINVAL;
        return -1;
    }
    return values[name];
}

long pathconf(const char* path, int name)
{
    OE_UNUSED(path);
    return fpathconf(-1, name);
}
