// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_EPOLL_H
#define _OE_SYSCALL_SYS_EPOLL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/syscall/signal.h>
#include <openenclave/internal/types.h>

OE_EXTERNC_BEGIN

#define OE_EPOLL_CTL_ADD 1
#define OE_EPOLL_CTL_DEL 2
#define OE_EPOLL_CTL_MOD 3

enum OE_EPOLL_EVENTS
{
    OE_EPOLLIN = 0x001,
    OE_EPOLLPRI = 0x002,
    OE_EPOLLOUT = 0x004,
    OE_EPOLLRDNORM = 0x040,
    OE_EPOLLRDBAND = 0x080,
    OE_EPOLLWRNORM = 0x100,
    OE_EPOLLWRBAND = 0x200,
    OE_EPOLLMSG = 0x400,
    OE_EPOLLERR = 0x008,
    OE_EPOLLHUP = 0x010,
    OE_EPOLLRDHUP = 0x2000,
    OE_EPOLLEXCLUSIVE = 1u << 28,
    OE_EPOLLWAKEUP = 1u << 29,
    OE_EPOLLONESHOT = 1u << 30,
    OE_EPOLLET = 1u << 31
};

#define __OE_EPOLL_DATA oe_epoll_data
#define __OE_EPOLL_DATA_T oe_epoll_data_t
#include <openenclave/internal/syscall/sys/bits/epoll_data.h>
#undef __OE_EPOLL_DATA
#undef __OE_EPOLL_DATA_T

#define __OE_EPOLL_EVENT oe_epoll_event
#include <openenclave/internal/syscall/sys/bits/epoll_event.h>
#undef __OE_EPOLL_EVENT

int oe_epoll_create(int size);

int oe_epoll_create1(int flags);

int oe_epoll_ctl(int epfd, int op, int fd, struct oe_epoll_event* event);

int oe_epoll_wait(
    int epfd,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout);

int oe_epoll_pwait(
    int epfd,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout,
    const oe_sigset_t* sigmask);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_EPOLL_H */
