// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_DEVICE_H
#define _OE_DEVICE_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/bits/devids.h>
#include <openenclave/corelibc/errno.h>
#include <openenclave/internal/epoll_ops.h>
#include <openenclave/internal/eventfd_ops.h>
#include <openenclave/internal/fd.h>
#include <openenclave/internal/fs_ops.h>
#include <openenclave/internal/sock_ops.h>

OE_EXTERNC_BEGIN

typedef enum _oe_device_type
{
    OE_DEVICE_TYPE_NONE = 0,

    OE_DEVICETYPE_FILESYSTEM,

    // This entry describes a file in the hosts's file system
    OE_DEVICETYPE_DIRECTORY,

    // This entry describes an internet socket
    OE_DEVICETYPE_FILE,

    // This entry describes an enclave to enclave
    OE_DEVICETYPE_SOCKET,

    // This entry describes an epoll device
    OE_DEVICETYPE_EPOLL,

    // This entry describes an eventfd device
    OE_DEVICETYPE_EVENTFD
} oe_device_type_t;

// Ready mask. Tracks the values for epoll
static const uint64_t OE_READY_IN = 0x00000001;
static const uint64_t OE_READY_PRI = 0x00000002;
static const uint64_t OE_READY_OUT = 0x00000004;
static const uint64_t OE_READY_ERR = 0x00000008;
static const uint64_t OE_READY_HUP = 0x00000010;
static const uint64_t OE_READY_RDNORM = 0x00000040;
static const uint64_t OE_READY_RDBAND = 0x00000080;
static const uint64_t OE_READY_WRNORM = 0x00000100;
static const uint64_t OE_READY_WRBAND = 0x00000200;
static const uint64_t OE_READY_MSG = 0x00000400;
static const uint64_t OE_READY_RDHUP = 0x00002000;

typedef struct _oe_device oe_device_t;

struct _oe_device
{
    /* Type of this device: OE_DEVID_FILE or OE_DEVID_SOCKET. */
    oe_device_type_t type;
    uint64_t devid; // Index of the device into the device table.

    /* sizeof additional data. To get a pointer to the device private data,
     * ptr = (oe_file_device_t)(devptr+1); usually sizeof(oe_file_t) or
     * sizeof(oe_socket_t).
     */
    size_t size;
    const char* devicename;

    union {
        oe_device_ops_t* base;
        oe_fs_ops_t* fs;
        oe_sock_ops_t* socket;
        oe_epoll_ops_t* epoll;
        oe_eventfd_ops_t* eventfd;
    } ops;
};

uint64_t oe_allocate_devid(uint64_t devid);
int oe_release_devid(uint64_t devid);

int oe_set_devid_device(uint64_t devid, oe_device_t* pdevice);
oe_device_t* oe_get_devid_device(uint64_t devid);
oe_device_t* oe_clone_device(oe_device_t* pdevice);

int oe_device_init(); // Overridable function to set up device structures. Shoud
                      // be ommited when new interface is complete.

int oe_device_addref(uint64_t devid);

int oe_device_release(uint64_t devid);

int oe_remove_device();

ssize_t oe_read(int fd, void* buf, size_t count);

ssize_t oe_write(int fd, const void* buf, size_t count);

int oe_close(int fd);

int oe_ioctl(int fd, unsigned long request, ...);

/* Set the default device for this thread (used in lieu of the mount table). */
int oe_set_thread_device(uint64_t devid);

/* Clear the default device for this thread. */
int oe_clear_thread_device(void);

/* Get the default device for this thread. */
uint64_t oe_get_thread_device(void);

OE_EXTERNC_END

#endif // _OE_DEVICE_H
