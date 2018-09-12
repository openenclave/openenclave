// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_SAFECRT_H
#define _OE_SAFECRT_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

oe_result_t oe_memcpy_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes);

oe_result_t oe_memmove_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes);

oe_result_t oe_strncat_s(
    char* dst,
    size_t dst_size,
    const char* src,
    size_t count);

#endif // _OE_SAFECRT_H
