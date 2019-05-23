// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYS_POLL_H
#define _OE_SYS_POLL_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** OE names:
**
**==============================================================================
*/

// clang-format off
#define OE_POLLIN     0x001
#define OE_POLLPRI    0x002
#define OE_POLLOUT    0x004
#define OE_POLLRDNORM 0x040
#define OE_POLLRDBAND 0x080
#define OE_POLLWRNORM 0x100
#define OE_POLLWRBAND 0x200
#define OE_POLLMSG    0x400
#define OE_POLLRDHUP  0x2000
#define OE_POLLERR    0x008
#define OE_POLLHUP    0x010
#define OE_POLLNVAL   0x020
// clang-format on

typedef unsigned long int oe_nfds_t;

struct oe_pollfd
{
    int fd;            /* File descriptor to poll.  */
    short int events;  /* Types of events poller cares about.  */
    short int revents; /* Types of events that actually occurred.  */
};

int oe_poll(struct oe_pollfd* fds, oe_nfds_t nfds, int timeout);

/*
**==============================================================================
**
** Standard-C names:
**
**==============================================================================
*/

#if defined(OE_NEED_STDC_NAMES)

#define POLLIN OE_POLLIN
#define POLLPRI OE_POLLPRI
#define POLLOUT OE_POLLOUT
#define POLLRDNORM OE_POLLRDNORM
#define POLLRDBAND OE_POLLRDBAND
#define POLLWRNORM OE_POLLWRNORM
#define POLLWRBAND OE_POLLWRBAND
#define POLLMSG OE_POLLMSG
#define POLLRDHUP OE_POLLRDHUP
#define POLLERR OE_POLLERR
#define POLLHUP OE_POLLHUP
#define POLLNVAL OE_POLLNVAL

struct pollfd
{
    int fd;
    short int events;
    short int revents;
};

typedef oe_nfds_t nfds_t;

OE_INLINE int poll(struct pollfd* fds, nfds_t nfds, int timeout)
{
    return oe_poll((struct oe_pollfd*)fds, nfds, timeout);
}

#endif /* defined(OE_NEED_STDC_NAMES) */

OE_EXTERNC_END

#endif /* _OE_SYS_POLL_H */
