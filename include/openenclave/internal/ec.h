// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#ifndef _OE_EC_INTERNAL_H
#define _OE_EC_INTERNAL_H

#include "crypto/ec.h"

OE_EXTERNC_BEGIN

/**
 * Reads a private EC key from PEM data
 *
 * This function reads a private EC key from PEM data with the following PEM
 * headers.
 *
 *     -----BEGIN PRIVATE KEY-----
 *     ...
 *     -----END PRIVATE KEY-----
 *
 * The caller is responsible for releasing the key by passing it to
 * oe_ec_private_key_free().
 *
 * @param private_key initialized key handle upon return
 * @param pem_data zero-terminated PEM data
 * @param pem_size size of the PEM data (including the zero-terminator)
 *
 * @return OE_OK upon success
 */
oe_result_t oe_ec_private_key_read_pem(
    oe_ec_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size);

/**
 * Digitally signs a message with a private EC key
 *
 * This function uses a private EC key to sign a message with the given hash.
 *
 * @param private_key private EC key of signer
 * @param hash_type type of hash parameter
 * @param hash_data hash of the message being signed
 * @param hash_size size of the hash data
 * @param signature signature buffer
 * @param[in,out] signature_size buffer size (in); signature size (out)
 *
 * @return OE_OK on success
 * @return OE_BUFFER_TOO_SMALL signature buffer is too small
 */
oe_result_t oe_ec_private_key_sign(
    const oe_ec_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size);

OE_EXTERNC_END

#endif /* _OE_EC_INTERNAL_H */
