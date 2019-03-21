// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

// clang-format off
#include <openenclave/enclave.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/internal/epoll.h>
#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/internal/device.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/print.h>
// clang-format on

#define printf oe_host_printf

static uint32_t poll_eventmask_to_epoll(uint32_t poll_event)

{
    uint32_t epoll_mask = 0;

    if (poll_event & POLLIN)
    {
        epoll_mask |= OE_EPOLLIN;
    }
    if (poll_event & POLLPRI)
    {
        epoll_mask |= OE_EPOLLPRI;
    }
    if (poll_event & POLLOUT)
    {
        epoll_mask |= OE_EPOLLOUT;
    }
    if (poll_event & POLLRDNORM)
    {
        epoll_mask |= OE_EPOLLRDNORM;
    }
    if (poll_event & POLLRDBAND)
    {
        epoll_mask |= OE_EPOLLRDBAND;
    }
    if (poll_event & POLLWRNORM)
    {
        epoll_mask |= OE_EPOLLWRNORM;
    }
    if (poll_event & POLLWRBAND)
    {
        epoll_mask |= OE_EPOLLWRBAND;
    }
    if (poll_event & POLLMSG)
    {
        epoll_mask |= OE_EPOLLMSG;
    }
    if (poll_event & POLLREMOVE)
    {
        /* ignored. but should complain */
    }
    if (poll_event & POLLRDHUP)
    {
        epoll_mask |= OE_EPOLLRDHUP;
    }
    if (poll_event & POLLERR)
    {
        epoll_mask |= OE_EPOLLERR;
    }
    if (poll_event & POLLHUP)
    {
        epoll_mask |= OE_EPOLLHUP;
    }
    if (poll_event & POLLNVAL)
    {
        /* ignored but should complain */
    }

    return epoll_mask;
}

static uint32_t epoll_eventmask_to_poll(uint32_t epoll_event)

{
    uint32_t poll_mask = 0;

    if (epoll_event & OE_EPOLLIN)
    {
        poll_mask |= POLLIN;
    }
    if (epoll_event & OE_EPOLLPRI)
    {
        poll_mask |= POLLPRI;
    }
    if (epoll_event & OE_EPOLLOUT)
    {
        poll_mask |= POLLOUT;
    }
    if (epoll_event & OE_EPOLLRDNORM)
    {
        poll_mask |= POLLRDNORM;
    }
    if (epoll_event & OE_EPOLLRDBAND)
    {
        poll_mask |= POLLRDBAND;
    }
    if (epoll_event & OE_EPOLLWRNORM)
    {
        poll_mask |= POLLWRNORM;
    }
    if (epoll_event & OE_EPOLLWRBAND)
    {
        poll_mask |= POLLWRBAND;
    }
    if (epoll_event & OE_EPOLLMSG)
    {
        poll_mask |= POLLMSG;
    }
    if (epoll_event & OE_EPOLLERR)
    {
        poll_mask |= POLLERR;
    }
    if (epoll_event & OE_EPOLLHUP)
    {
        poll_mask |= POLLHUP;
    }
    if (epoll_event & OE_EPOLLRDHUP)
    {
        poll_mask |= POLLRDHUP;
    }

    return poll_mask;
}

// Poll is implemented in terms of epoll.

int oe_poll(struct oe_pollfd* fds, nfds_t nfds, int timeout_ms)
{
    int retval = -1;
    int epoll_fd = -1;
    nfds_t i = 0;
    struct oe_epoll_event* rev =
        oe_malloc(sizeof(struct oe_epoll_event) * nfds);

    epoll_fd = oe_epoll_create1(0);
    if (epoll_fd < 0)
    {
        return epoll_fd;
    }

    for (i = 0; i < nfds; i++)
    {
        if (fds[i].fd >= 0)
        {
            struct oe_epoll_event ev = {
                .data.fd = fds[i].fd,
                .events = poll_eventmask_to_epoll((uint32_t)fds[i].events)};

            retval = oe_epoll_ctl(epoll_fd, OE_EPOLL_CTL_ADD, fds[i].fd, &ev);
            if (retval < 0)
            {
                goto done;
            }
        }
    }

    retval = oe_epoll_wait(epoll_fd, rev, (int)nfds, timeout_ms);
    if (retval < 0)
    {
        goto done;
    }
    /* output */
    for (i = 0; i < nfds; i++)
    {
        if (fds[i].fd == -1)
        {
            fds[i].revents = POLLNVAL;
            continue;
        }

        int j = 0;
        for (j = 0; j < retval; j++)
        {
            if (rev[j].data.fd < 0)
            {
                continue;
            }
            if (fds[i].fd == rev[j].data.fd)
            {
                fds[i].revents =
                    (int16_t)epoll_eventmask_to_poll(rev[j].events);
                rev[j].data.fd = -1; /* done with this ev desc */
                break;
            }
        }
    }

done:
    oe_free(rev);
    return retval;
}
