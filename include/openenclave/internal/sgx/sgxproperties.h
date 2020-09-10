// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SGX_PROPERTIES_H
#define _OE_INTERNAL_SGX_PROPERTIES_H
#include <string.h>

OE_INLINE bool oe_sgx_is_valid_product_id(uint16_t x)
{
    return x < OE_UINT16_MAX;
}

OE_INLINE bool oe_sgx_is_valid_security_version(uint16_t x)
{
    return x < OE_UINT16_MAX;
}

OE_INLINE bool oe_sgx_is_valid_num_heap_pages(uint64_t x)
{
    return x < OE_UINT64_MAX;
}

OE_INLINE bool oe_sgx_is_valid_num_stack_pages(uint64_t x)
{
    return x < OE_UINT64_MAX;
}

OE_INLINE bool oe_sgx_is_valid_num_tcs(uint64_t x)
{
    return x <= OE_SGX_MAX_TCS;
}

OE_INLINE bool oe_sgx_is_unset_uuid(uint8_t* x)
{
    uint8_t zeros[16] = {0};
    return memcmp(x, zeros, sizeof(zeros)) == 0;
}

OE_INLINE bool oe_sgx_is_valid_attributes(uint64_t x)
{
    /* Check for illegal bits */
    if (x & ~(OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT | OE_SGX_FLAGS_KSS |
              OE_SGX_FLAGS_PROVISION_KEY | OE_SGX_FLAGS_EINITTOKEN_KEY))
        return false;

    /* Check for missing MODE64BIT */
    if (!(x & OE_SGX_FLAGS_MODE64BIT))
        return false;

    return true;
}

#endif /* _OE_INTERNAL_SGX_PROPERTIES_H */
