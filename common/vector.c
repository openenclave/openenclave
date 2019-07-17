// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/vector.h>

oe_result_t oe_vector_pack(
    const oe_vector_t* vectors,
    size_t count,
    void** buf_out,
    size_t* buf_size_out)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_vector_t* buf = NULL;
    size_t buf_size = 0;
    size_t data_size = 0;

    if (buf_out)
        *buf_out = NULL;

    if (buf_size_out)
        *buf_size_out = 0;

    /* Reject invalid parameters. */
    if (count < 0 || (count > 0 && !vectors) || !buf_out || !buf_size_out)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Handle zero-sized count up front. */
    if (count == 0)
    {
        if (vectors)
        {
            if (!(buf = oe_calloc(1, sizeof(uint64_t))))
                OE_RAISE(OE_OUT_OF_MEMORY);

            buf_size = sizeof(uint64_t);
        }

        *buf_out = buf;
        *buf_size_out = buf_size;
        buf = NULL;

        result = OE_OK;
        goto done;
    }

    /* Calculate the total number of data bytes. */
    for (size_t i = 0; i < count; i++)
        data_size += vectors[i].size;

    /* Caculate the total size of the resulting buffer. */
    buf_size = (sizeof(oe_vector_t) * (size_t)count) + data_size;

    /* Allocate the output buffer. */
    if (!(buf = oe_calloc(1, buf_size)))
        OE_RAISE(OE_OUT_OF_MEMORY);

    /* Initialize the array elements. */
    {
        uint8_t* p = (uint8_t*)&buf[count];
        size_t n = data_size;
        size_t i;

        for (i = 0; i < count; i++)
        {
            const size_t size = vectors[i].size;
            const void* data = vectors[i].data;

            if (size)
            {
                buf[i].size = size;
                buf[i].data = (void*)(p - (uint8_t*)buf);

                if (!data)
                    OE_RAISE(OE_INVALID_PARAMETER);

                OE_CHECK(oe_memcpy_s(p, n, data, size));
                p += size;
                n -= size;
            }
        }

        /* Fail if the data was not exhausted. */
        if (n != 0)
            OE_RAISE(OE_FAILURE);
    }

    *buf_out = buf;
    *buf_size_out = buf_size;
    buf = NULL;
    result = OE_OK;

done:

    if (buf)
        oe_free(buf);

    return result;
}

oe_vector_t* oe_vector_relocate(void* buf, size_t vector_count)
{
    oe_vector_t* vectors = (oe_vector_t*)buf;

    if (!buf)
        return NULL;

    ptrdiff_t addend = (ptrdiff_t)buf;

    for (size_t i = 0; i < vector_count; i++)
    {
        if (vectors[i].data)
            vectors[i].data = (uint8_t*)vectors[i].data + addend;
    }

    return vectors;
}
