// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/*
**==============================================================================
**
** host_socket.h
**
**     Definition of the host_socket internal types and data
**
**==============================================================================
*/

#ifndef _OE_INTERNAL_HOSTSOCK_H
#define _OE_INTERNAL_HOSTSOCK_H

#include <openenclave/internal/device.h>

OE_EXTERNC_BEGIN

oe_device_t* oe_get_hostsock_device(void);

int oe_register_hostsock_device(void);

void oe_handle_hostsock_ocall(void* args);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_HOSTSOCK_H */
