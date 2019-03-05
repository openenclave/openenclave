// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_FD_H
#define _OE_FD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_device oe_device_t;

void oe_release_fd(int fd);

oe_device_t* oe_set_fd_device(int fd, oe_device_t* device);

oe_device_t* oe_get_fd_device(int fd);

int oe_assign_fd_device(oe_device_t* device);

// Take a host fd from hostfs or host_sock and return the enclave file
// descriptor index If the host fd is not found, we return -1
ssize_t oe_map_host_fd(uint64_t host_fd);

OE_EXTERNC_END

#endif // _OE_FD_H
