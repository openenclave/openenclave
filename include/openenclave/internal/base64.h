// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_BASE64_H
#define _OE_INTERNAL_BASE64_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>

OE_EXTERNC_BEGIN

/**
 * Encode data in base-64 format.
 *
 * This function encodes data in base-64 format. If **add_line_breaks** is true,
 * line breaks are injected after every 64 characters and after the final
 * characters.
 *
 * @param raw_data the input buffer.
 * @param raw_size the size of the input buffer.
 * @param add_line_breaks add lines breaks if true.
 * @param base64_data the output bufer (may be null if **base64_size** is zero).
 * @param base64_data[in,out] size of buffer (in); required size (out).
 *
 * @return OE_OK success.
 * @return OE_INVALID_PARAMETER a parameter is invalid.
 * @return OE_BUFFER_TOO_SMALL the output buffer is too small and 
 *         **base64_size** contains the required size.
 * @return OE_FAILURE general failure.
 */
oe_result_t oe_base64_encode(
    const uint8_t* raw_data,
    size_t raw_size,
    bool add_line_breaks,
    uint8_t* base64_data,
    size_t* base64_size);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_BASE64_H */
