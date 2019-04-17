
/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_EPOLL_H
#define _OE_EPOLL_H

#include <openenclave/corelibc/signal.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/internal/device.h>

OE_EXTERNC_BEGIN

OE_PACK_BEGIN
typedef struct _oe_device_notifications
{
    uint32_t event_mask; // oe_epoll_event.event
    union {
        uint64_t data;
        struct
        {
            uint32_t epoll_fd; // Enclave fd for the
            uint32_t
                list_idx; // On the host side we set this into the event data
        };
    };
} oe_device_notifications_t;
OE_PACK_END

struct oe_device_notification_args
{
    uint64_t num_notifications;
    // struct oe_device_notifications events[];
};

oe_device_t* oe_epoll_get_epoll(void);

/* internal signalling */
void oe_signal_device_notification(oe_device_t* pdevice, uint32_t event_mask);

void oe_broadcast_device_notification(void);
int oe_wait_device_notification(int timeout);
void oe_clear_device_notification(void);

typedef union _oe_ev_data {
    struct
    {
        uint32_t epoll_enclave_fd;
        uint32_t event_list_idx;
    };
    uint64_t data;
} oe_ev_data_t;

int oe_get_epoll_events(
    int epollfd,
    size_t maxevents,
    struct oe_epoll_event* pevents);

void oe_handle_hostepoll_ocall(void* args);

OE_EXTERNC_END

#endif /* _OE_EPOLL_H */
