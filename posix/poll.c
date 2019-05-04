// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/corelibc/sys/socket.h>
#include <openenclave/corelibc/unistd.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/thread.h>
#include <openenclave/internal/trace.h>
#include "device.h"
#include "epoll.h"
#include "fdtable.h"

// Poll uses much of the infrastructure from epoll.

int oe_poll(struct oe_pollfd* fds, nfds_t nfds, int timeout_ms)
{
    oe_device_t* pepoll = NULL;
    int retval = -1;
    int epfd = -1;
    nfds_t i = 0;
    struct oe_epoll_event* rev = NULL;
    bool has_host_wait;

    if ((epfd = oe_epoll_create1(0)) < 0)
    {
        oe_errno = OE_EBADF;
        goto done;
    }

    if (!(rev = oe_malloc(sizeof(struct oe_epoll_event) * nfds)))
    {
        oe_errno = OE_ENOMEM;
        goto done;
    }

    if (!(pepoll = oe_fdtable_get(epfd, OE_DEVICE_TYPE_EPOLL)))
    {
        OE_TRACE_ERROR("pepoll=%p, epfd=%d", pepoll, epfd);
        goto done;
    }

    if (pepoll->ops.epoll->add_event_data == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("oe_errno=%d", oe_errno);
        goto done;
    }

    for (i = 0; i < nfds; i++)
    {
        if (fds[i].fd >= 0)
        {
            struct oe_epoll_event ev = {.data.fd = fds[i].fd,
                                        .events = (uint32_t)fds[i].events};

            retval = (*pepoll->ops.epoll->add_event_data)(
                epfd, fds[i].fd, ev.events, ev.data.u64);
            if (retval < 0)
            {
                OE_TRACE_ERROR("nfds=%lu retval=%d", nfds, retval);
                goto done;
            }
        }
    }

    has_host_wait = true;

    if (!pepoll)
    {
        OE_TRACE_ERROR("pepoll=%p nfds=%lu", pepoll, nfds);
        retval = -1; // errno is already set
        goto done;
    }

    if (pepoll->ops.epoll->poll == NULL)
    {
        oe_errno = OE_EINVAL;
        OE_TRACE_ERROR("poll=%p oe_errno=%d", pepoll, oe_errno);
        retval = -1;
        goto done;
    }

    // Start an outboard waiter if host involved
    // search polled device list for host involved  2Do
    if (has_host_wait)
    {
        if ((retval = (*pepoll->ops.epoll->poll)(
                 epfd, fds, (size_t)nfds, timeout_ms)) < 0)
        {
            OE_TRACE_ERROR("retval=%d", retval);
            oe_errno = OE_EINVAL;
            goto done;
        }
    }

    // We check immedately because we might have gotten lucky and had stuff come
    // in immediately. If so we skip the wait
    retval = oe_get_epoll_events(epfd, (size_t)nfds, rev);

    if (retval == 0)
    {
        if (oe_wait_device_notification(timeout_ms) < 0)
        {
            oe_errno = OE_EPROTO;
            OE_TRACE_ERROR("oe_errno=%d", oe_errno);
            goto done;
        }

        retval = oe_get_epoll_events(epfd, (size_t)nfds, rev);
    }

    if (retval < 0)
    {
        OE_TRACE_ERROR("retval=%d nfds=%lu", retval, nfds);
        goto done;
    }

    /* output */
    for (i = 0; i < nfds; i++)
    {
        if (fds[i].fd == -1)
        {
            fds[i].revents = OE_POLLNVAL;
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
                fds[i].revents = (int16_t)rev[j].events;
                rev[j].data.fd = -1; /* done with this ev desc */
                break;
            }
        }
    }

done:

    if (epfd != -1)
        oe_close(epfd);

    if (rev)
        oe_free(rev);

    return retval;
}
