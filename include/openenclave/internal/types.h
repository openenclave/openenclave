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

#endif /* _OE_INTERNAL_TYPES_H */
