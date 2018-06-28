// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BUF_H
#define _OE_BUF_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

typedef struct _oe_outbuf
{
    void* buffer;
    size_t size;
    size_t offset;
} oe_outbuf_t;

oe_result_t oe_outbuf_start(
    oe_outbuf_t* buf,
    void* buffer,
    size_t* size,
    size_t alignment);

OE_INLINE void* oe_outbuf_end(oe_outbuf_t* buf)
{
    if (!buf->buffer)
        return NULL;

    return buf->buffer + buf->offset;
}

void oe_outbuf_append(oe_outbuf_t* buf, const void* s, size_t n);

oe_result_t oe_outbuf_finish(oe_outbuf_t* buf, size_t* size);

OE_EXTERNC_END

#endif /* _OE_BUF_H */
