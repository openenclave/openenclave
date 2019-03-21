// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/corelibc/sys/poll.h>
#include <openenclave/corelibc/sys/select.h>
#include <openenclave/internal/defs.h>
#include <poll.h>

OE_STATIC_ASSERT(sizeof(struct oe_pollfd) == sizeof(struct pollfd));
OE_CHECK_FIELD(struct oe_pollfd, struct pollfd, fd);
OE_CHECK_FIELD(struct oe_pollfd, struct pollfd, events);
OE_CHECK_FIELD(struct oe_pollfd, struct pollfd, revents);
