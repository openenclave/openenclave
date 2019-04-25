// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_DEVICE_H
#define _OE_BITS_DEVICE_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

oe_result_t oe_set_device_for_current_thread(const char* device_name);

oe_result_t oe_clear_device_for_current_thread(void);

uint64_t oe_get_device_for_current_thread(void);

OE_EXTERNC_END

#endif // _OE_BITS_DEVICE_H
