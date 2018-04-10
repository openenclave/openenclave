// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_PROPERTIES_H
#define _OE_BITS_PROPERTIES_H

#include "../properties.h"

OE_INLINE bool OE_ValidProductID(uint16_t x)
{
    return (x >= 0 && x < OE_MAX_UINT16) ? true : false;
}

OE_INLINE bool OE_ValidSecurityVersion(uint16_t x)
{
    return (x >= 0 && x < OE_MAX_UINT16) ? true : false;
}

OE_INLINE bool OE_ValidNumHeapPages(uint64_t x)
{
    return (x > 0 && x < OE_MAX_UINT64) ? true : false;
}

OE_INLINE bool OE_ValidNumStackPages(uint64_t x)
{
    return (x > 0 && x < OE_MAX_UINT64) ? true : false;
}

OE_INLINE bool OE_ValidNumTCS(uint64_t x)
{
    return (x > 0 && x < OE_MAX_UINT64) ? true : false;
}

OE_INLINE bool OE_ValidAttributes(uint64_t x)
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
