// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BUF_H
#define _OE_BUF_H

#include <openenclave/bits/defs.h>
#include <openenclave/bits/types.h>
#include <stddef.h>
#include <stdint.h>

OE_EXTERNC_BEGIN

/*
**==============================================================================
**
** oe_buf_t:
**
**==============================================================================
*/

#define OE_BUF_INITIALIZER \
    {                      \
        NULL, 0, 0         \
    }

typedef struct _oe_buf
{
    void* data;
    uint32_t size;
    uint32_t cap;
} oe_buf_t;

void oe_buf_release(oe_buf_t* buf);

int oe_buf_clear(oe_buf_t* buf);

int oe_buf_reserve(oe_buf_t* buf, uint32_t cap);

int oe_buf_resize(oe_buf_t* buf, uint32_t new_size);

int oe_buf_append(oe_buf_t* buf, const void* data, uint32_t size);

/*
**==============================================================================
**
** oe_bufu32_t:
**
**==============================================================================
*/

#define OE_BUF_U32_INITIALIZER \
    {                          \
        NULL, 0, 0             \
    }

typedef struct _bufu32
{
    uint32_t* data;
    uint32_t size;
    uint32_t cap;
} oe_bufu32_t;

void oe_bufu32_release(oe_bufu32_t* buf);

void oe_bufu32_clear(oe_bufu32_t* buf);

int oe_bufu32_resize(oe_bufu32_t* buf, uint32_t new_size);

int oe_bufu32_append(oe_bufu32_t* buf, const uint32_t* data, uint32_t size);

OE_EXTERNC_END

#endif /* _OE_BUF_H */
