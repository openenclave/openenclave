// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openenclave/internal/raise.h>
#include <openenclave/internal/safecrt.h>
#include "common.h"

oe_result_t oe_memcpy_s(
    void* dst,
    size_t dst_size,
    const void* src,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;

    if (dst == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (src == NULL || dst_size < num_bytes)
    {
        memset(dst, 0, dst_size);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Reject overlapping buffers. */
    if ((dst >= src && ((uint8_t*)dst < (uint8_t*)src + num_bytes)) ||
        (dst < src && ((uint8_t*)dst + dst_size > (uint8_t*)src)))
    {
        memset(dst, 0, dst_size);
        OE_RAISE(OE_OVERLAPPED_COPY);
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
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;

    if (dst == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (src == NULL || dst_size < num_bytes)
    {
        memset(dst, 0, dst_size);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    memmove(dst, src, num_bytes);
    result = OE_OK;
done:
    return result;
}

oe_result_t oe_memset_s(void* dst, size_t dst_size, int value, size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;
    volatile unsigned char* p = dst;

    if (dst == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The C11 standard states that memset_s will store `value` in
     * `dst[0...dst_size]` even during a runtime violation. */
    if (dst_size < num_bytes)
    {
        result = OE_INVALID_PARAMETER;
        num_bytes = dst_size;
    }
    else
    {
        result = OE_OK;
    }

    /* memset_s cannot be optimized away by the compiler */
    while (num_bytes--)
        *p++ = (unsigned char)value;

done:
    return result;
}

OE_INLINE oe_result_t _oe_validate_string(char* str, size_t size)
{
    if (str != NULL && size > 0)
        return OE_OK;
    return OE_INVALID_PARAMETER;
}

OE_INLINE void _oe_fill_string(char* str, size_t size)
{
    OE_UNUSED(str);
    OE_UNUSED(size);
#ifndef NDEBUG
    // Fill memory with pattern.
    memset(str, 0xFD, size);
#endif
}

OE_INLINE void _oe_reset_string(char* str, size_t size)
{
    *str = '\0';
    _oe_fill_string(str + 1, size - 1);
}

oe_result_t oe_strncat_s(
    char* dst,
    size_t dst_size,
    const char* src,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;
    char* p = dst;
    size_t available = dst_size;

    /* Reject invalid parameters. */
    OE_CHECK(_oe_validate_string(dst, dst_size));

    if (src == NULL)
    {
        _oe_reset_string(dst, dst_size);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    while (available > 0 && *p != 0)
    {
        if (p == src)
        {
            _oe_reset_string(dst, dst_size);
            OE_RAISE(OE_OVERLAPPED_COPY);
        }

        p++;
        available--;
    }

    /* Not null terimated. */
    if (available == 0)
    {
        _oe_reset_string(dst, dst_size);
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy from the end of the destination string. */
    result = oe_strncpy_s(p, available, src, num_bytes);

    if (result != OE_OK)
    {
        _oe_reset_string(dst, dst_size);
        OE_RAISE(result);
    }

    result = OE_OK;
done:
    return result;
}

oe_result_t oe_strncpy_s(
    char* dst,
    size_t dst_size,
    const char* src,
    size_t num_bytes)
{
    oe_result_t result = OE_FAILURE;
    const char* current_src = src;
    char* current_dst = dst;
    size_t current_dst_size = dst_size;

    /* Reject invalid parameters. */
    OE_CHECK(_oe_validate_string(dst, dst_size));

    if (src == NULL)
    {
        _oe_reset_string(dst, dst_size);
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Copy until we hit one of the terminating conditions. */
    while (current_dst_size != 0)
    {
        /* If we detect an overlapped copy, we will return an error. */
        if (current_dst == src || current_src == dst)
        {
            _oe_reset_string(dst, dst_size);
            OE_RAISE(OE_OVERLAPPED_COPY);
        }

        /* Successful terminating conditions for strncpy_s. */
        if (num_bytes == 0 || *current_src == '\0')
        {
            *current_dst = '\0';
            result = OE_OK;
            goto done;
        }

        /* Copy and contine looping. */
        *current_dst++ = *current_src++;
        current_dst_size--;
        num_bytes--;
    }

    /* Destination buffer is not large enough. */
    _oe_reset_string(dst, dst_size);
    OE_RAISE(OE_BUFFER_TOO_SMALL);

done:
    return result;
}
