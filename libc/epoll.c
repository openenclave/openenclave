// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/syscall/sys/epoll.h>
#include <sys/epoll.h>

OE_STATIC_ASSERT(sizeof(struct oe_epoll_event) == sizeof(struct epoll_event));
// OE_CHECK_FIELD(struct oe_epoll_event, struct epoll_event, data);
