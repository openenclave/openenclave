// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_BUF_H
#define _OE_INTERNAL_BUF_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_buf
{
    uint8_t* data;
    size_t size;
    size_t capacity;
} oe_buf_t;

void oe_buf_open(oe_buf_t* buf);

int oe_buf_pack(
    oe_buf_t* buf,
    void** ptr,
    const void* data,
    size_t size,
    void* (*realloc_func)(void*, size_t));

int oe_buf_pack_str(
    oe_buf_t* buf,
    void** ptr,
    const char* str,
    void* (*realloc_func)(void*, size_t));

void* oe_buf_close(oe_buf_t* buf, void* (*realloc_func)(void*, size_t));

void* oe_buf_relocate(void* data, size_t size);

OE_EXTERNC_END

#endif /* _OE_INTERNAL_BUF_H */
