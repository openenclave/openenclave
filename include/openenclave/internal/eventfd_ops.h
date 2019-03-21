
/* Copyright (c) Microsoft Corporation. All rights reserved. */
/* Licensed under the MIT License. */

#ifndef __OE_EVENTFD_OPS_H__
#define __OE_EVENTFD_OPS_H__

#include <openenclave/internal/device_ops.h>

#ifdef cplusplus
extern "C"
{
#endif

    struct oe_eventfd_event;

    typedef struct _oe_device oe_device_t;

    typedef struct _oe_eventfd_ops
    {
        oe_device_ops_t base;
        oe_device_t* (
            *eventfd)(oe_device_t* eventfd_device, uint64_t initval, int flags);
    } oe_eventfd_ops_t;

#ifdef cplusplus
}
#endif

#endif
