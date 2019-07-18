// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/buf.h>

#if defined(OE_BUILD_ENCLAVE)
#include <openenclave/corelibc/assert.h>
#include <openenclave/corelibc/stdlib.h>
#include <openenclave/corelibc/string.h>
#define strlen oe_strlen
#define assert oe_assert
#define abort oe_abort
#else
#include <assert.h>
#include <stdlib.h>
#include <string.h>
#endif

/*
**==============================================================================
**
** Local definitions.
**
**==============================================================================
*/

#define MAGIC 0x4cb90f08b66a43df

#define ALIGNMENT 8

/* object descriptor. */
typedef struct _desc
{
    uint64_t magic;
    const uint8_t* ptr;
    const uint8_t* data;
    size_t size;
} desc_t;

static size_t _align(size_t n)
{
    return (n + ALIGNMENT - 1) / ALIGNMENT * ALIGNMENT;
}

static int _reserve(
    oe_buf_t* buf,
    size_t capacity,
    void* (*realloc_func)(void*, size_t))
{
    int ret = -1;

    if (!buf)
        goto done;

    if (capacity > buf->capacity)
    {
        const size_t chunk_size = 4096;
        capacity = (capacity + chunk_size - 1) / chunk_size * chunk_size;
        void* data;

        if (!(data = (*realloc_func)(buf->data, capacity)))
            goto done;

        buf->data = data;
        buf->capacity = capacity;
    }

    ret = 0;

done:
    return ret;
}

static int _append(
    oe_buf_t* buf,
    const void* data,
    size_t size,
    void* (*realloc_func)(void*, size_t))
{
    int ret = -1;

    if (!buf)
        goto done;

    if (_reserve(buf, buf->size + size + ALIGNMENT, realloc_func) != 0)
        goto done;

    memcpy(buf->data + buf->size, data, size);
    buf->size += _align(size);

    ret = 0;

done:
    return ret;
}

static desc_t* _next(desc_t* desc)
{
    return (desc_t*)((uint8_t*)(desc + 1) + desc->size);
}

static int _relocate(desc_t* root, desc_t* desc)
{
    desc_t* p = root;

    /* Search for the block that contains a pointer to this block. */
    while (p && p->magic == MAGIC && p != desc)
    {
        /* If the p-descriptor contains a pointer to this block. */
        if (desc->ptr >= p->data && desc->ptr < p->data + p->size)
        {
            uint8_t* ptr = (uint8_t*)(desc + 1);
            uint8_t* ptrptr = (uint8_t*)(p + 1) + (desc->ptr - p->data);

            *(void**)ptrptr = ptr;
            return 0;
        }

        p = _next(p);
    }

    return -1;
}

/*
**==============================================================================
**
** Public definitions.
**
**==============================================================================
*/

void oe_buf_open(oe_buf_t* buf)
{
    if (buf)
        memset(buf, 0, sizeof(oe_buf_t));
}

int oe_buf_pack(
    oe_buf_t* buf,
    void** ptr,
    const void* data,
    size_t size,
    void* (*realloc_func)(void*, size_t))
{
    int ret = -1;
    desc_t desc;

    if (!buf)
        goto done;

    if (!data)
    {
        ret = 0;
        goto done;
    }

    desc.magic = MAGIC;
    desc.ptr = (const uint8_t*)ptr;
    desc.data = data;
    desc.size = _align(size);

    if (_append(buf, &desc, sizeof(desc), realloc_func) != 0)
        goto done;

    if (_append(buf, data, size, realloc_func) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}

int oe_buf_pack_str(
    oe_buf_t* buf,
    void** ptr,
    const char* str,
    void* (*realloc_func)(void*, size_t))
{
    int ret = -1;

    if (!buf)
        goto done;

    if (!str)
    {
        ret = 0;
        goto done;
    }

    ret = oe_buf_pack(buf, ptr, str, strlen(str) + 1, realloc_func);

done:
    return ret;
}

void* oe_buf_close(oe_buf_t* buf, void* (*realloc_func)(void*, size_t))
{
    void* ret = NULL;
    desc_t desc;

    if (!buf)
        goto done;

    desc.magic = MAGIC;
    desc.ptr = NULL;
    desc.data = NULL;
    desc.size = 0;

    if (_append(buf, &desc, sizeof(desc), realloc_func) != 0)
        goto done;

    ret = buf->data;

done:
    return ret;
}

void* oe_buf_relocate(void* data, size_t size)
{
    void* ret = NULL;
    desc_t* root = (desc_t*)data;
    desc_t* p = root;

    if (!root || size < sizeof(desc_t) || root->magic != MAGIC || root->ptr)
        goto done;

    while ((p = _next(p)))
    {
        if (p->magic != MAGIC)
            goto done;

        /* If this is the null terminator then break out. */
        if (!p->data)
            break;

#if 0
        printf("===\n");
        printf("p->ptr=%p\n", p->ptr);
        printf("p->data=%p\n", p->data);
        printf("p->size=%zu\n", p->size);
#endif

        if (_relocate(root, p) != 0)
            goto done;
    }

    ret = (root + 1);

done:
    return ret;
}
