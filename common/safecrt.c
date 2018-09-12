// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include "common.h"

oe_result_t oe_memcpy_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes
)
{
    oe_result_t result = OE_FAILURE;

    if (dst == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (num_bytes == 0)
    {
        /* nothing to do */        
    }
    else 
    {
        if (src == NULL || dst_size < num_bytes)
        {
            /* zeroes the destination buffer */
            memset(dst, 0, num_bytes);
            OE_RAISE(OE_INVALID_PARAMETER);
        }
    }

    memcpy(dst, src, num_bytes);
    result = OE_OK;
done:
    
    return result;
}

oe_result_t oe_memmove_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes
)
{
    oe_result_t result = OE_FAILURE;
    char* p = (char*)dst;
    const char* q = (const char*)src;
    size_t n = num_bytes;

    if (dst == NULL || src == NULL || dst_size < num_bytes)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Inline implementation of oe_memmove.
    // This avoids allocating a temporary buffer.
    if (p != q && n > 0)
    {
        if (p <= q)
        {
            memcpy(p, q, n);
        }
        else
        {
            for (q += n, p += n; n--; p--, q--)
                p[-1] = q[-1];
        }
    }

    result = OE_OK;
done:

    return result;
}

#if 0
oe_result_t oe_strncat_s(
    char* dst,
    size_t dst_size,
    const char* src,
    size_t count)
{
    char *p = NULL;
    size_t available = 0;

    if (count == 0 && dst == NULL && dst_size == 0)
    {
        /* this case is allowed; nothing to do */
        return OE_OK;
    }

    /* validation section */
    if (!dst || dst_size == 0)
        OE_RAISE(OE_INVALID_PARAMETER);
   
    if (src == NULL)
    {
        // Reset string.
        *dst = '\0';
#ifndef NDEBUG
        // Fill memory with pattern.
        memset(dst+1, 0xFD, dst_size-1);
#endif
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    p = dst;
    available = dst_size;
    while (available > 0 && *p != 0)
    {
        p++;
        available--;
    }

    if (available == 0)
    {
        // Reset string.
        *dst = '\0';
#ifndef NDEBUG
        // Fill memory with pattern.
        memset(dst+1, 0xFD, dst_size-1);
#endif
        // Not null terminated.
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    if (count == (size_t)-1)
    {
        while ((*p++ = *src++) != 0 && --available > 0)
        {
        }
    }
    else
    {
        if (available < count)
            OE_RAISE(OE_BUFFER_TOO_SMALL);

        while (count > 0 && (*p++ = *src++) != 0 && --available > 0)
        {
            count--;
        }
        if (count == 0)
        {
            *p = 0;
        }
    }

    if (available == 0)
    {
        if (count == (size_t)-1)
        {
            dst[dst_size - 1] = 0;
            _RETURN_TRUNCATE;
        }
        _RESET_STRING(_DEST, _SIZE);
        _RETURN_BUFFER_TOO_SMALL(_DEST, _SIZE);
    }
    _FILL_STRING(_DEST, _SIZE, _SIZE - available + 1);
    
done:
    return result;
}
#endif
