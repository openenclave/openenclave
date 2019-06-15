// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_TYPES_H
#define _OE_SYSCALL_TYPES_H

#include <openenclave/bits/types.h>
#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

typedef int64_t oe_host_fd_t;

/* Version of struct oe_pollfd with wider descriptor. */
struct oe_host_pollfd
{
    oe_host_fd_t fd;
    short int events;
    short int revents;
};

OE_STATIC_ASSERT(sizeof(struct oe_host_pollfd) == (2 * sizeof(uint64_t)));
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_host_pollfd, fd) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_host_pollfd, events) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_host_pollfd, revents) == 10);

OE_EXTERNC_END

#endif // _OE_SYSCALL_TYPES_H
