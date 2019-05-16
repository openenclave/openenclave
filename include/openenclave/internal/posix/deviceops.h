// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_POSIX_DEVICEOPS_H
#define _OE_POSIX_DEVICEOPS_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <openenclave/internal/posix/types.h>
#include <openenclave/internal/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_device oe_device_t;

typedef struct _oe_device_ops
{
    int (*release)(oe_device_t* dev);

} oe_device_ops_t;

OE_EXTERNC_END

#endif // _OE_POSIX_DEVICEOPS_H
