// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_TYPES_H
#define _OE_INTERNAL_TYPES_H

#include <openenclave/bits/defs.h>

typedef OE_ALIGNED(OE_PAGE_SIZE) struct _oe_page
{
    unsigned char data[OE_PAGE_SIZE];
} oe_page;

OE_STATIC_ASSERT(__alignof(oe_page) == OE_PAGE_SIZE);

typedef enum _oe_type {
    OE_NONE_T,
    OE_CHAR_T,
    OE_UCHAR_T,
    OE_WCHAR_T,
    OE_SHORT_T,
    OE_INT_T,
    OE_LONG_T,
    OE_USHORT_T,
    OE_UINT_T,
    OE_ULONG_T,
    OE_BOOL_T,
    OE_INT8_T,
    OE_UINT8_T,
    OE_INT16_T,
    OE_UINT16_T,
    OE_INT32_T,
    OE_UINT32_T,
    OE_INT64_T,
    OE_UINT64_T,
    OE_FLOAT_T,
    OE_DOUBLE_T,
    OE_SIZE_T,
    OE_SSIZE_T,
    OE_STRUCT_T,
    OE_VOID_T,
} oe_type_t;

typedef void* (*oe_alloc_proc)(size_t size);

typedef void (*oe_dealloc_proc_t)(void* ptr);

#endif /* _OE_INTERNAL_TYPES_H */
