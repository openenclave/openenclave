// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "buf.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
**==============================================================================
**
** oe_buf_t:
**
**==============================================================================
*/

#define BUF_CHUNK_SIZE 1024

void oe_buf_release(oe_buf_t* buf)
{
    if (buf && buf->data)
    {
        memset(buf->data, 0xDD, buf->size);
        free(buf->data);
    }

    memset(buf, 0x00, sizeof(oe_buf_t));
}

int oe_buf_clear(oe_buf_t* buf)
{
    if (!buf)
        return -1;

    buf->size = 0;

    return 0;
}

int oe_buf_reserve(oe_buf_t* buf, uint32_t cap)
{
    if (!buf)
        return -1;

    /* If capacity is bigger than current capacity */
    if (cap > buf->cap)
    {
        void* new_data;
        uint32_t new_cap;

        /* Double current capacity (will be zero the first time) */
        new_cap = buf->cap * 2;

        /* If capacity still insufficent, round to multiple of chunk size */
        if (cap > new_cap)
        {
            const uint32_t N = BUF_CHUNK_SIZE;
            new_cap = (cap + N - 1) / N * N;
        }

        /* Expand allocation */
        if (!(new_data = realloc(buf->data, new_cap)))
            return -1;

        buf->data = new_data;
        buf->cap = new_cap;
    }

    return 0;
}

int oe_buf_resize(oe_buf_t* buf, uint32_t new_size)
{
    uint8_t* data;

    if (!buf)
        return -1;

    if (new_size == 0)
    {
        oe_buf_release(buf);
        memset(buf, 0, sizeof(oe_buf_t));
        return 0;
    }

    if (!(data = realloc(buf->data, new_size)))
        return -1;

    if (new_size > buf->size)
        memset(data + buf->size, 0, new_size - buf->size);

    buf->data = data;
    buf->size = new_size;
    buf->cap = new_size;

    return 0;
}

int oe_buf_append(oe_buf_t* buf, const void* data, uint32_t size)
{
    uint32_t new_size;

    /* Check arguments */
    if (!buf || !data)
        return -1;

    /* If zero-sized, then success */
    if (size == 0)
        return 0;

    /* Compute the new size */
    new_size = buf->size + size;

    /* If insufficient capacity to hold new data */
    if (new_size > buf->cap)
    {
        int err;

        if ((err = oe_buf_reserve(buf, new_size)) != 0)
            return err;
    }

    /* Copy the data */
    memcpy((unsigned char*)buf->data + buf->size, data, size);
    buf->size = new_size;

    return 0;
}

/*
**==============================================================================
**
** oe_bufu32_t:
**
**==============================================================================
*/

void oe_bufu32_release(oe_bufu32_t* buf)
{
    oe_buf_t tmp;

    tmp.data = buf->data;
    tmp.size = buf->size * sizeof(uint32_t);
    tmp.cap = buf->cap * sizeof(uint32_t);
    oe_buf_release(&tmp);
}

void oe_bufu32_clear(oe_bufu32_t* buf)
{
    oe_bufu32_release(buf);
    buf->data = NULL;
    buf->size = 0;
    buf->cap = 0;
}

int oe_bufu32_append(oe_bufu32_t* buf, const uint32_t* data, uint32_t size)
{
    oe_buf_t tmp;

    tmp.data = buf->data;
    tmp.size = buf->size * sizeof(uint32_t);
    tmp.cap = buf->cap * sizeof(uint32_t);

    if (oe_buf_append(&tmp, data, size * sizeof(uint32_t)) != 0)
    {
        return -1;
    }

    buf->data = tmp.data;
    buf->size = tmp.size / sizeof(uint32_t);
    buf->cap = tmp.cap / sizeof(uint32_t);

    return 0;
}

int oe_bufu32_resize(oe_bufu32_t* buf, uint32_t new_size)
{
    oe_buf_t tmp;

    tmp.data = buf->data;
    tmp.size = buf->size * sizeof(uint32_t);
    tmp.cap = buf->cap * sizeof(uint32_t);

    if (oe_buf_resize(&tmp, new_size * sizeof(uint32_t)) != 0)
        return -1;

    buf->data = tmp.data;
    buf->size = tmp.size / sizeof(uint32_t);
    buf->cap = tmp.cap / sizeof(uint32_t);

    return 0;
}
