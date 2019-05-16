
/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_POSIX_EVENTFDOPS_H
#define _OE_POSIX_EVENTFDOPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include "deviceops.h"

OE_EXTERNC_BEGIN

struct oe_eventfd_event;

typedef struct _oe_device oe_device_t;
typedef struct _oe_fd oe_fd_t;

typedef struct _oe_eventfd_device_ops
{
    oe_device_ops_t base;

    oe_fd_t* (*eventfd)(oe_device_t* dev, unsigned int initval, int flags);

} oe_eventfd_device_ops_t;

OE_EXTERNC_END

#endif /* _OE_POSIX_EVENTFDOPS_H */
