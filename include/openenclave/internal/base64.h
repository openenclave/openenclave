// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_BASE64_H
#define _OE_INTERNAL_BASE64_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

oe_result_t oe_base64_encode(
    const uint8_t* raw_data,
    size_t raw_size,
    bool add_line_breaks,
    uint8_t* base64_data,
    size_t* base64_size);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_BASE64_H */
