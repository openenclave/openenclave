// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_SYS_SELECT_H
#define _OE_SYSCALL_SYS_SELECT_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/syscall/sys/time.h>
#include <openenclave/internal/syscall/unistd.h>

OE_EXTERNC_BEGIN

#define OE_FD_SETSIZE 1024

#define __OE_FD_SET oe_fd_set
#include <openenclave/internal/syscall/sys/bits/fd_set.h>
#undef __OE_FD_SET

int oe_select(
    int nfds,
    oe_fd_set* readfds,
    oe_fd_set* writefds,
    oe_fd_set* exceptfds,
    struct oe_timeval* timeout);

void OE_FD_CLR(int fd, oe_fd_set* set);

int OE_FD_ISSET(int fd, oe_fd_set* set);

void OE_FD_SET(int fd, oe_fd_set* set);

void OE_FD_ZERO(oe_fd_set* set);

OE_EXTERNC_END

#endif /* _OE_SYSCALL_SYS_SELECT_H */
