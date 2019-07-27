// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/enclave.h>

oe_result_t oe_get_seal_key_by_policy_v2(
    oe_seal_policy_t seal_policy,
    uint8_t** _key_buffer,
    size_t* _key_buffer_size,
    uint8_t** _key_info,
    size_t* _key_info_size)
{
    OE_UNUSED(seal_policy);
    OE_UNUSED(_key_buffer);
    OE_UNUSED(_key_buffer_size);
    OE_UNUSED(_key_info);
    OE_UNUSED(_key_info_size);

    return OE_UNSUPPORTED;
}

void oe_free_seal_key(
    uint8_t* key_buffer, /** [in] If non-NULL, frees the key buffer. */
    uint8_t* key_info)   /** [in] If non-NULL, frees the key info. */
{
    OE_UNUSED(key_buffer);
    OE_UNUSED(key_info);
}

oe_result_t oe_get_seal_key_v2(
    const uint8_t* key_info,
    size_t key_info_size,
    uint8_t** key_buffer,
    size_t* key_buffer_size)
{
    OE_UNUSED(key_info);
    OE_UNUSED(key_info_size);
    OE_UNUSED(key_buffer);
    OE_UNUSED(key_buffer_size);

    return OE_UNSUPPORTED;
}
