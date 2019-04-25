// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_POSIX_EPOLL_H
#define _OE_INTERNAL_POSIX_EPOLL_H

#include <openenclave/corelibc/signal.h>
#include <openenclave/corelibc/sys/epoll.h>
#include "device.h"

OE_EXTERNC_BEGIN

OE_PACK_BEGIN
typedef struct _oe_device_notifications
{
    /* oe_epoll_event.event */
    uint32_t event_mask;
    union {
        uint64_t data;
        struct
        {
            /* Enclave fd for the epoll device. */
            uint32_t epoll_fd;
            /* On the host side we set this into the event data. */
            uint32_t list_idx;
        };
    };
} oe_device_notifications_t;
OE_PACK_END

struct oe_device_notification_args
{
    uint64_t num_notifications;
};

typedef union _oe_ev_data {
    struct
    {
        uint32_t epoll_enclave_fd;
        uint32_t event_list_idx;
    };
    uint64_t data;
} oe_ev_data_t;

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
