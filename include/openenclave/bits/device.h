// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_DEVICE_H
#define _OE_BITS_DEVICE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Identifiers for well-known device types. */
enum
{
    OE_DEVID_NONE,
    OE_DEVID_HOSTFS,
    OE_DEVID_SGXFS,
    OE_DEVID_HOSTSOCK,
    OE_DEVID_ENCLAVESOCK,
    OE_DEVID_HOSTEPOLL,
    OE_DEVID_EVENTFD,
};

oe_result_t oe_set_thread_devid(uint64_t devid);

oe_result_t oe_clear_thread_devid(void);

uint64_t oe_get_thread_devid(void);

OE_EXTERNC_END

#endif // _OE_BITS_DEVICE_H
