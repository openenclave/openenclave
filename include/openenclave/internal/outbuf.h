// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

/**
 * @file asn1.h
 *
 * This file defines the oe_outbuf_t type, which is used to simplify functions
 * that handle output buffers in which the size is both an input parameter
 * output parameter. The value of the input parameter specifies the size of 
 * the caller's buffer. The value of the output parameter specifies the
 * required size of the buffer. Further, the caller can pass NULL for the
 * buffer and zero for the size as a way of determining the required buffer
 * size. Consider the following example.
 *
 *     ````
 *     oe_result_t foo(uint8_t* buf, size_t* size);
 *     ````
 *
 * The caller may call this function with a NULL buffer or a buffer that is 
 * too short, in which case the function returns OE_BUFFER_TOO_SMALL as shown 
 * below.
 *
 *     ```
 *     size_t size = 0;
 *     oe_result_t r = foo(NULL, &size);
 *     ```
 *
 * In this example, the function sets **size** to the required size of the 
 * buffer so the caller may now obtain a buffer of sufficient size and call the
 * function again as follows.
 *
 *     ```
 *     size_t size = 0;
 *     oe_result_t r = foo(NULL, &size);
 *
 *     buffer = malloc(size);
 *     oe_result_t r = foo(buffer, &size);
 *     ```
 *
 * If the function returns OE_OK, then **size** contains the extact size
 * of the buffer (which could be smaller than the original value of the
 * **size** parameter).
 *
 * Functions that handle these buffers can be rather tricky to code correctly,
 * so oe_outbuf_t and its supporting functions simplify this effort. Consider
 * an implementation that uses oe_outbuf_t.
 *
 *     ```
 *     oe_result_t foo(uint8_t* buf, size_t* size);
 *     {
 *         oe_outbuf_t outbuf;
 *         oe_result r;
 *
 *         r = oe_outbuf_start(&outbuf, buf, size);
 *         if (r != OE_OK)
 *             return r;
 *
 *         // Append without regard to null buffers or buffer overflows.
 *         oe_outbuf_append(&outbuf, "red", 3);
 *         oe_outbuf_append(&outbuf, "green", 5);
 *         oe_outbuf_append(&outbuf, "blue", 4);
 *         oe_outbuf_append(&outbuf, "", 1);
 *
 *         r = oe_outbuf_finish(&outbuf, size);
 *         if (r != OE_OK)
 *             return r;
 *
 *         return OE_OK;
 *     }
 *     ```
 */

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
