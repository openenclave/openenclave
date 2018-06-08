// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_BITS_PROPERTIES_H
#define _OE_BITS_PROPERTIES_H

#include <openenclave/properties.h>

OE_INLINE bool oe_sgx__valid_product_id(uint16_t x)
{
    return x < OE_MAX_UINT16;
}

OE_INLINE bool oe_sgx__valid_security_version(uint16_t x)
{
    return x < OE_MAX_UINT16;
}

OE_INLINE bool oe_sgx__valid_num_heap_pages(uint64_t x)
{
    return x < OE_MAX_UINT64;
}

OE_INLINE bool oe_sgx__valid_num_stack_pages(uint64_t x)
{
    return x < OE_MAX_UINT64;
}

OE_INLINE bool oe_sgx__valid_num_tcs(uint64_t x)
{
    return x <= OE_SGX_MAX_TCS;
}

OE_INLINE bool oe_sgx__valid_attributes(uint64_t x)
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
