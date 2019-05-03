// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_POSIX_H
#define _OE_INTERNAL_POSIX_H

#include <openenclave/bits/defs.h>
#include <openenclave/corelibc/sys/epoll.h>
#include <openenclave/internal/types.h>

/*
**==============================================================================
**
** posix.h
**
**     This file defines shared definitions used across the POSIX EDL interface.
**
**==============================================================================
*/

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** Identifiers for well-known device types.
**
**==============================================================================
*/

enum
{
    OE_DEVID_NONE,
    OE_DEVID_HOSTFS,
    OE_DEVID_SGXFS,
    OE_DEVID_HOSTSOCK,
    OE_DEVID_ENCLAVESOCK,
    OE_DEVID_EPOLL,
    OE_DEVID_EVENTFD,
};

/*
**==============================================================================
**
** oe_host_fd_t:
**
**==============================================================================
*/

typedef int64_t oe_host_fd_t;

/*
**==============================================================================
**
** oe_register_posix_ocall_function_table():
** oe_register_posix_ecall_function_table():
**
**==============================================================================
*/

#define OE_POSIX_OCALL_FUNCTION_TABLE_ID 0
#define OE_POSIX_ECALL_FUNCTION_TABLE_ID 0

/* Register the OCALL table needed by the POSIX interface (host side). */
void oe_register_posix_ocall_function_table(void);

/* Register the ECALL table needed by the POSIX interface (enclave side). */
void oe_register_posix_ecall_function_table(void);

/*
**==============================================================================
**
** oe_device_notifications_t:
**
**     This structure overlays 'struct epoll_event' from <corelibc/sys/epoll.h>,
**     which is identical to the same structure in both MUSL and glibc. It is
**     packed to match the definitions in those implementations.
**
**==============================================================================
*/

OE_PACK_BEGIN
typedef struct _oe_device_notifications /* overlays 'struct epoll_event' */
{
    uint32_t events;
    struct
    {
        /* Enclave fd for the epoll device. */
        int epoll_fd;
        /* On the host side we set this into the event data. */
        uint32_t list_idx;
    } data;
} oe_device_notifications_t;
OE_PACK_END

OE_STATIC_ASSERT(
    sizeof(oe_device_notifications_t) == sizeof(struct oe_epoll_event));

/*
**==============================================================================
**
** oe_ev_data_t:
**
**==============================================================================
*/

typedef union _oe_ev_data {
    struct
    {
        uint32_t epoll_enclave_fd;
        uint32_t event_list_idx;
    };
    uint64_t data;
} oe_ev_data_t;

OE_EXTERNC_END

#endif /* _OE_INTERNAL_POSIX_H */
