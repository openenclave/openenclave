// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#ifndef _OE_GCM_H
#define _OE_GCM_H

#include <openenclave/bits/result.h>
#include <openenclave/bits/types.h>

OE_EXTERNC_BEGIN

oe_result_t oe_aes_gcm_encrypt(
    const uint8_t* key,
    size_t key_size,
    const uint8_t* iv,
    size_t iv_size,
    const uint8_t* aad,
    size_t aad_size,
    const uint8_t* input,
    size_t input_size,
    uint8_t* output,
    uint8_t* tag);

oe_result_t oe_aes_gcm_decrypt(
    const uint8_t* key,
    size_t key_size,
    const uint8_t* iv,
    size_t iv_size,
    const uint8_t* aad,
    size_t aad_size,
    const uint8_t* input,
    size_t input_size,
    uint8_t* output,
    const uint8_t* tag);

OE_EXTERNC_END

#endif /* _OE_GCM_H */
