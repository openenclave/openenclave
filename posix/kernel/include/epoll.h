// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_POSIX_EPOLL_H
#define _OE_INTERNAL_POSIX_EPOLL_H

#include <openenclave/corelibc/signal.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/internal/posix.h>
#include "device.h"

OE_EXTERNC_BEGIN

oe_device_t* oe_epoll_get_epoll(void);

void oe_signal_device_notification(oe_device_t* pdevice, uint32_t event_mask);

void oe_broadcast_device_notification(void);

int oe_wait_device_notification(int timeout);

void oe_clear_device_notification(void);

int oe_get_epoll_events(
    int epfd,
    size_t maxevents,
    struct oe_epoll_event* pevents);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_POSIX_EPOLL_H */
