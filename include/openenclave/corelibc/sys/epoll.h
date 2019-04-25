// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_EPOLL_H
#define _OE_SYS_EPOLL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/signal.h>
#include <openenclave/internal/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

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
#include <openenclave/corelibc/sys/bits/epoll_data.h>
#undef __OE_EPOLL_DATA
#undef __OE_EPOLL_DATA_T

#define __OE_EPOLL_EVENT oe_epoll_event
#include <openenclave/corelibc/sys/bits/epoll_event.h>
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

/*
**==============================================================================
**
** standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define EPOLL_CTL_ADD OE_EPOLL_CTL_ADD
#define EPOLL_CTL_DEL OE_EPOLL_CTL_DEL
#define EPOLL_CTL_MOD OE_EPOLL_CTL_MOD

enum EPOLL_EVENTS
{
    EPOLLIN = OE_EPOLLIN,
    EPOLLPRI = OE_EPOLLPRI,
    EPOLLOUT = OE_EPOLLOUT,
    EPOLLRDNORM = OE_EPOLLRDNORM,
    EPOLLRDBAND = OE_EPOLLRDBAND,
    EPOLLWRNORM = OE_EPOLLWRNORM,
    EPOLLWRBAND = OE_EPOLLWRBAND,
    EPOLLMSG = OE_EPOLLMSG,
    EPOLLERR = OE_EPOLLERR,
    EPOLLHUP = OE_EPOLLHUP,
    EPOLLRDHUP = OE_EPOLLRDHUP,
    EPOLLEXCLUSIVE = OE_EPOLLEXCLUSIVE,
    EPOLLWAKEUP = OE_EPOLLWAKEUP,
    EPOLLONESHOT = OE_EPOLLONESHOT,
    EPOLLET = OE_EPOLLET,
};

#define __OE_EPOLL_DATA epoll_data
#define __OE_EPOLL_DATA_T epoll_data_t
#include <openenclave/corelibc/sys/bits/epoll_data.h>
#undef __OE_EPOLL_DATA
#undef __OE_EPOLL_DATA_T

#define __OE_EPOLL_EVENT epoll_event
#include <openenclave/corelibc/sys/bits/epoll_event.h>
#undef __OE_EPOLL_EVENT

OE_INLINE int epoll_create(int size)
{
    return oe_epoll_create(size);
}

OE_INLINE int epoll_create1(int flags)
{
    return oe_epoll_create(flags);
}

OE_INLINE int epoll_ctl(int epfd, int op, int fd, struct epoll_event* event)
{
    return oe_epoll_ctl(epfd, op, fd, (struct oe_epoll_event*)event);
}

OE_INLINE int epoll_wait(
    int epfd,
    struct epoll_event* events,
    int maxevents,
    int timeout)
{
    return oe_epoll_wait(
        epfd, (struct oe_epoll_event*)events, maxevents, timeout);
}

OE_INLINE int epoll_pwait(
    int epfd,
    struct oe_epoll_event* events,
    int maxevents,
    int timeout,
    const oe_sigset_t* sigmask)
{
    return oe_epoll_pwait(
        epfd, (struct oe_epoll_event*)events, maxevents, timeout, sigmask);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_EPOLL_H */
