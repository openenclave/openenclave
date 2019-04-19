/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_EVENTFD_H
#define _OE_EVENTFD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/posix/device.h>

OE_EXTERNC_BEGIN

enum
{
    OE_EFD_SEMAPHORE = 00000001,
    OE_EFD_CLOEXEC = 02000000,
    OE_EFD_NONBLOCK = 00004000
};

typedef uint64_t oe_eventfd_t;

oe_device_t* oe_get_eventfd_device(void);

int oe_eventfd(unsigned int count, int flags);

int oe_eventfd_read(int fd, oe_eventfd_t* value);

int oe_eventfd_write(int fd, oe_eventfd_t value);

OE_EXTERNC_END

#endif /* _OE_EVENTFD_H */
