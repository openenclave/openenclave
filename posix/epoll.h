// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_EPOLL_H
#define _OE_POSIX_EPOLL_H

#include <openenclave/corelibc/signal.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/internal/device/device.h>

OE_EXTERNC_BEGIN

oe_device_t* oe_epoll_get_epoll(void);

OE_EXTERNC_END

#endif /* _OE_POSIX_EPOLL_H */
