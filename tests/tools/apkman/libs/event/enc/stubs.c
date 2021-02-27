// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>
#include <openenclave/internal/syscall/sys/syscall.h>
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>

#include <stdio.h>
#include <wchar.h>

int issetugid()
{
    return 0;
}

// Lib event tries opening pipes on sockets.
// We can either compile libevent without pipes
// or just fail the pipe calls so that livevent doesn't
// use them.
int pipe(int fd, int m)
{
    OE_UNUSED(fd);
    OE_UNUSED(m);
    return -1;
}

int pipe2(int fd, int m)
{
    OE_UNUSED(fd);
    OE_UNUSED(m);
    return -1;
}

static const uint64_t _SEC_TO_MSEC = 1000UL;
static const uint64_t _MSEC_TO_USEC = 1000UL;
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
