// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_PROPERTIES_H
#define _OE_BITS_PROPERTIES_H

#include <openenclave/properties.h>

OE_INLINE bool OE_SGXValidProductID(uint16_t x)
{
    return x < OE_MAX_UINT16;
}

OE_INLINE bool OE_SGXValidSecurityVersion(uint16_t x)
{
    return x < OE_MAX_UINT16;
}

OE_INLINE bool OE_SGXValidNumHeapPages(uint64_t x)
{
    return x < OE_MAX_UINT64;
}

OE_INLINE bool OE_SGXValidNumStackPages(uint64_t x)
{
    return x < OE_MAX_UINT64;
}

OE_INLINE bool OE_SGXValidNumTCS(uint64_t x)
{
    return x < OE_MAX_UINT64;
}

OE_INLINE bool OE_SGXValidAttributes(uint64_t x)
{
    /* Check for illegal bits */
    if (x & ~(OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT))
        return false;

    /* Check for missing MODE64BIT */
    if (!(x & OE_SGX_FLAGS_MODE64BIT))
        return false;

    return true;
}

#endif /* _OE_BITS_PROPERTIES_H */
