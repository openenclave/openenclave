// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_SYSCALL_TYPES_H
#define _OE_SYSCALL_TYPES_H

#include <openenclave/bits/edl/syscall_types.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/bits/poll.h>
#include <openenclave/internal/defs.h>

OE_EXTERNC_BEGIN

OE_STATIC_ASSERT(sizeof(struct oe_host_pollfd) == (2 * sizeof(uint64_t)));
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_host_pollfd, fd) == 0);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_host_pollfd, events) == 8);
OE_STATIC_ASSERT(OE_OFFSETOF(struct oe_host_pollfd, revents) == 10);

OE_EXTERNC_END

#endif // _OE_SYSCALL_TYPES_H
