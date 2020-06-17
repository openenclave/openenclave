// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

#include <openenclave/corelibc/stdlib.h>
#include <openenclave/internal/syscall/fdtable.h>
#include <openenclave/internal/syscall/raise.h>
#include <openenclave/internal/syscall/sys/poll.h>
#include "syscall_t.h"

int oe_poll(struct oe_pollfd* fds, oe_nfds_t nfds, int timeout)
{
    int ret = -1;
    int retval = -1;
    struct oe_host_pollfd* host_fds = NULL;
    oe_nfds_t i;

    if (!fds || nfds == 0)
        OE_RAISE_ERRNO(OE_EINVAL);

    if (!(host_fds = oe_calloc(nfds, sizeof(struct oe_host_pollfd))))
        OE_RAISE_ERRNO(OE_ENOMEM);

    /* Convert enclave fds to host fds. */
    for (i = 0; i < nfds; i++)
    {
        oe_host_fd_t host_fd;
        oe_fd_t* desc;

        /* Fetch the fd struct for this fd struct. */
        if (!(desc = oe_fdtable_get(fds[i].fd, OE_FD_TYPE_ANY)))
            OE_RAISE_ERRNO(OE_EBADF);

        /* Get the host fd for this fd struct. */
        if ((host_fd = desc->ops.fd.get_host_fd(desc)) == -1)
            OE_RAISE_ERRNO(OE_EBADF);

        host_fds[i].events = fds[i].events;
        host_fds[i].fd = host_fd;
    }

    if (oe_syscall_poll_ocall(&retval, host_fds, nfds, timeout) != OE_OK)
        OE_RAISE_ERRNO(OE_EINVAL);

    /* Update fds[] with any recieved events. */
    for (i = 0; i < nfds; i++)
        fds[i].revents = host_fds[i].revents;

    ret = retval;

done:

    if (host_fds)
        oe_free(host_fds);

    return ret;
}
