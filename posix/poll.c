// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/device/device.h>
#include <openenclave/internal/device/fdtable.h>
#include <openenclave/internal/device/raise.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "epoll.h"

/* This module assumes that the following flags are consistent. */
OE_STATIC_ASSERT(OE_POLLIN == OE_EPOLLIN);
OE_STATIC_ASSERT(OE_POLLPRI == OE_EPOLLPRI);
OE_STATIC_ASSERT(OE_POLLOUT == OE_EPOLLOUT);
OE_STATIC_ASSERT(OE_POLLRDNORM == OE_EPOLLRDNORM);
OE_STATIC_ASSERT(OE_POLLRDBAND == OE_EPOLLRDBAND);
OE_STATIC_ASSERT(OE_POLLWRNORM == OE_EPOLLWRNORM);
OE_STATIC_ASSERT(OE_POLLWRBAND == OE_EPOLLWRBAND);
OE_STATIC_ASSERT(OE_POLLMSG == OE_EPOLLMSG);
OE_STATIC_ASSERT(OE_POLLRDHUP == OE_EPOLLRDHUP);
OE_STATIC_ASSERT(OE_POLLERR == OE_EPOLLERR);
OE_STATIC_ASSERT(OE_POLLHUP == OE_EPOLLHUP);

int oe_poll(struct oe_pollfd* fds, nfds_t nfds, int timeout)
{
    int ret = -1;
    int epfd = -1;
    nfds_t i = 0;
    struct oe_epoll_event* events = NULL;
    int num_events;

    /* Check for illegal parameters. */
    if (!fds || nfds >= OE_INT_MAX)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Create the epoll device. */
    if ((epfd = oe_epoll_create1(0)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    /* Call oe_epoll_ctl() for each poll file descriptor. */
    for (i = 0; i < nfds; i++)
    {
        const struct oe_pollfd* fd = &fds[i];
        struct oe_epoll_event event;

        memset(&event, 0, sizeof(event));
        event.data.fd = fd->fd;
        event.events = (uint32_t)fd->events;

        if (oe_epoll_ctl(epfd, OE_EPOLL_CTL_ADD, fd->fd, &event) == -1)
            OE_RAISE_ERRNO(oe_errno);
    }

    /* Allocate an array of epoll events. */
    if (!(events = oe_calloc(1, sizeof(struct oe_epoll_event) * nfds)))
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Call oe_epoll_wait() to wait for events. */
    if ((num_events = oe_epoll_wait(epfd, events, (int)nfds, timeout)) == -1)
        OE_RAISE_ERRNO(oe_errno);

    /* Convert epoll events back to poll file descriptors. */
    for (i = 0; i < nfds; i++)
    {
        struct oe_pollfd* fd = &fds[i];
        int j = 0;

        for (j = 0; j < num_events; j++)
        {
            if (fd->fd == events[j].data.fd)
            {
                fds[i].revents = (short int)events[j].events;
                break;
            }
        }
    }

    ret = num_events;

done:

    if (epfd != -1)
        oe_close(epfd);

    if (events)
        oe_free(events);

    return ret;
}
