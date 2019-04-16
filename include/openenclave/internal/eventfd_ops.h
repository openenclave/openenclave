
/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef _OE_EVENTFD_OPS_H
#define _OE_EVENTFD_OPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/device_ops.h>

OE_EXTERNC_BEGIN

struct oe_eventfd_event;

typedef struct _oe_device oe_device_t;

typedef struct _oe_eventfd_ops
{
    oe_device_ops_t base;
    oe_device_t* (
        *eventfd)(oe_device_t* eventfd_device, uint64_t initval, int flags);
} oe_eventfd_ops_t;

OE_EXTERNC_END

#endif /* _OE_EVENTFD_OPS_H */
