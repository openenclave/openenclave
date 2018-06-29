// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/outbuf.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

#ifdef OE_BUILD_ENCLAVE
#include <openenclave/internal/enclavelibc.h>
#define memcpy oe_memcpy
#define memset oe_memset
#else
#include <string.h>
#endif

oe_result_t oe_outbuf_start(
    oe_outbuf_t* buf,
    void* buffer,
    size_t* size,
    size_t alignment)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!buffer && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (oe_align_pointer(buffer, alignment) != buffer)
        OE_RAISE(OE_BAD_ALIGNMENT);

    buf->buffer = buffer;
    buf->size = *size;
    buf->offset = 0;

    result = OE_OK;

done:
    return result;
}

void oe_outbuf_append(oe_outbuf_t* buf, const void* s, size_t n)
{
    /* If any space remaining in the buffer */
    if (buf->offset < buf->size)
    {
        const size_t remaining = buf->size - buf->offset;
        const size_t m = (remaining < n) ? remaining : n;

        if (s)
            memcpy((uint8_t*)buf->buffer + buf->offset, s, m);
        else
            memset((uint8_t*)buf->buffer + buf->offset, 0, m);
    }

    buf->offset += n;
}

oe_result_t oe_outbuf_finish(oe_outbuf_t* buf, size_t* size)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (buf->offset > buf->size)
    {
        *size = buf->offset;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    *size = buf->offset;

    result = OE_OK;

done:
    return result;
}
