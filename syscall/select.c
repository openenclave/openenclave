// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/corelibc/assert.h>
#include <openenclave/corelibc/stdio.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/print.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/syscall/poll.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/sys/select.h>
#include <openenclave/internal/trace.h>

typedef struct _poll_fds
{
    oe_nfds_t size;
    struct oe_pollfd data[OE_FD_SETSIZE];
} poll_fds_t;

int _update_fds(poll_fds_t* fds, int fd, short events)
{
    int ret = -1;
    oe_nfds_t i;

    /* If the fd is already in the array, update it. */
    for (i = 0; i < fds->size; i++)
    {
        if (fds->data[i].fd == fd)
        {
            fds->data[i].events = events;
            ret = 0;
            goto done;
        }
    }

    /* If the array is exhausted. */
    if (fds->size == OE_COUNTOF(fds->data))
        goto done;

    /* Append the new element. */

    fds->data[fds->size].fd = fd;
    fds->data[fds->size].events = events;
    fds->data[fds->size].revents = 0;
    fds->size++;

    ret = 0;

done:
    return ret;
}

int _fdset_to_fds(poll_fds_t* fds, short events, oe_fd_set* set, int nfds)
{
    int ret = -1;
    int fd;

    for (fd = 0; fd < nfds; fd++)
    {
        if (OE_FD_ISSET(fd, set))
        {
            if (_update_fds(fds, fd, events) != 0)
                goto done;
        }
    }

    ret = 0;

done:
    return ret;
}

int _fds_to_fdset(poll_fds_t* fds, short revents, oe_fd_set* set)
{
    int num_ready = 0;
    oe_nfds_t i;

    for (i = 0; i < fds->size; i++)
    {
        const struct oe_pollfd* p = &fds->data[i];

        if ((p->revents & revents))
        {
            OE_FD_SET(p->fd, set);
            num_ready++;
        }
    }

    return num_ready;
}

int oe_select(
    int nfds,
    oe_fd_set* readfds,
    oe_fd_set* writefds,
    oe_fd_set* exceptfds,
    struct oe_timeval* timeout)
{
    int ret = -1;
    int num_ready = 0;
    poll_fds_t fds = {0};
    int poll_timeout = -1;

    if (timeout)
    {
        poll_timeout = (int)timeout->tv_sec * 1000;
        poll_timeout += (int)(timeout->tv_usec / 1000);
    }

    if (readfds)
    {
        const short events = OE_POLLIN | OE_POLLRDNORM | OE_POLLRDBAND;

        if (_fdset_to_fds(&fds, events, readfds, nfds) != 0)
            goto done;
    }

    if (writefds)
    {
        const short events = OE_POLLOUT | OE_POLLWRNORM | OE_POLLWRBAND;

        if (_fdset_to_fds(&fds, events, writefds, nfds) != 0)
            goto done;
    }

    if (exceptfds)
    {
        const short events = OE_POLLERR | OE_POLLHUP | OE_POLLRDHUP;

        if (_fdset_to_fds(&fds, events, exceptfds, nfds) != 0)
            goto done;
    }

    if ((ret = oe_poll(fds.data, fds.size, poll_timeout)) < 0)
        goto done;

    if (readfds)
        OE_FD_ZERO(readfds);

    if (writefds)
        OE_FD_ZERO(writefds);

    if (exceptfds)
        OE_FD_ZERO(exceptfds);

    if (readfds)
    {
        short events = OE_POLLIN | OE_POLLRDNORM | OE_POLLRDBAND;
        int n;

        if ((n = _fds_to_fdset(&fds, events, readfds)) > num_ready)
            num_ready += n;
    }

    if (writefds)
    {
        short events = OE_POLLOUT | OE_POLLWRNORM | OE_POLLWRBAND;
        int n;

        if ((n = _fds_to_fdset(&fds, events, writefds)) > num_ready)
            num_ready += n;
    }

    if (exceptfds)
    {
        short events = OE_POLLERR | OE_POLLHUP | OE_POLLRDHUP;
        int n;

        if ((n = _fds_to_fdset(&fds, events, exceptfds)) > num_ready)
            num_ready += n;
    }

    ret = num_ready;

done:

    return ret;
}

void OE_FD_CLR(int fd, oe_fd_set* set)
{
    if (fd >= 0)
    {
        uint64_t word = ((uint64_t)fd) / (8UL * sizeof(uint64_t));
        uint64_t bit = ((uint64_t)fd) % (8UL * sizeof(uint64_t));
        uint64_t mask = ~(1UL << bit);

        set->fds_bits[word] &= mask;
    }
    else
    {
        oe_assert("OE_FD_SET: out of bounds" == NULL);
    }
}

int OE_FD_ISSET(int fd, oe_fd_set* set)
{
    if (fd >= 0)
    {
        uint64_t word = ((uint64_t)fd) / (8UL * sizeof(uint64_t));
        uint64_t bit = ((uint64_t)fd) % (8UL * sizeof(uint64_t));
        uint64_t mask = (1UL << bit);

        return !!(set->fds_bits[word] & mask);
    }
    else
    {
        oe_assert("OE_FD_ISSET: out of bounds" == NULL);
        return 0;
    }
}

void OE_FD_SET(int fd, oe_fd_set* set)
{
    if (fd >= 0)
    {
        uint64_t word = ((uint64_t)fd) / (8UL * sizeof(uint64_t));
        uint64_t bit = ((uint64_t)fd) % (8UL * sizeof(uint64_t));
        uint64_t mask = (1UL << bit);

        set->fds_bits[word] |= mask;
    }
    else
    {
        oe_assert("OE_FD_SET: out of bounds" == NULL);
    }
}

void OE_FD_ZERO(oe_fd_set* set)
{
    if (set)
    {
        /* oe_memset_s() cannot fail with these parameters. */
        oe_memset_s(set, sizeof(oe_fd_set), 0, sizeof(oe_fd_set));
    }
}
