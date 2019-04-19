// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_DEVID_H
#define _OE_BITS_DEVID_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

/* Identifiers for well-known device types. */
enum
{
    OE_DEVID_NULL,
    OE_DEVID_HOSTFS,
    OE_DEVID_SGXFS,
    OE_DEVID_HOSTSOCK,
    OE_DEVID_ENCLAVESOCK,
    OE_DEVID_EPOLL,
    OE_DEVID_EVENTFD,
};

OE_EXTERNC_END

#endif /* _OE_BITS_DEVID_H */
