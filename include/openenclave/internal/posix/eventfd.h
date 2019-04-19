/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_INTERNAL_POSIX_EVENTFD_H
#define _OE_INTERNAL_POSIX_EVENTFD_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/corelibc/sys/eventfd.h>
#include <openenclave/internal/posix/device.h>

OE_EXTERNC_BEGIN

oe_device_t* oe_get_eventfd_device(void);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_POSIX_EVENTFD_H */
