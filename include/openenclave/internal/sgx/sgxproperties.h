// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_INTERNAL_SGX_PROPERTIES_H
#define _OE_INTERNAL_SGX_PROPERTIES_H
#include <openenclave/internal/constants_x64.h>
#include <string.h>

/* OE_SGX_ENCLAVE_SIZE_OFFSET is defined in constants_x64.h
 * and is used by enter.S. Enforce the check here such that
 * enter.S does not need to depend on the public sgxproperties.h
 * header (required by oe_sgx_enclave_properties_t and
 * oe_sgx_enclave_image_info_t) */
OE_STATIC_ASSERT(
    OE_SGX_ENCLAVE_SIZE_OFFSET ==
    OE_OFFSETOF(oe_sgx_enclave_properties_t, image_info) +
        OE_OFFSETOF(oe_sgx_enclave_image_info_t, enclave_size));

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

OE_INLINE bool oe_sgx_is_valid_start_address(uint64_t x)
{
    return ((x != 0) && !(x % OE_PAGE_SIZE));
}

OE_INLINE bool oe_sgx_is_unset_uuid(uint8_t* x)
{
    uint8_t zeros[16] = {0};
    return memcmp(x, zeros, sizeof(zeros)) == 0;
}

OE_INLINE bool oe_sgx_is_valid_attributes(uint64_t x)
{
    /* Check for illegal bits */
    if (x & ~(OE_SGX_FLAGS_DEBUG | OE_SGX_FLAGS_MODE64BIT | OE_SGX_FLAGS_KSS))
        return false;

    /* Check for missing MODE64BIT */
    if (!(x & OE_SGX_FLAGS_MODE64BIT))
        return false;

    return true;
}

#endif /* _OE_INTERNAL_SGX_PROPERTIES_H */
