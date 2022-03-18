// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/cipher.h>

#include <openenclave/internal/crypto/gcm.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/safemath.h>
#include <stdlib.h>

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
    size_t output_size,
    uint8_t* tag)
{
    const mbedtls_cipher_info_t* info = NULL;
    mbedtls_cipher_context_t gcm;
    oe_result_t result = OE_OK;
    uint8_t* buffer = NULL;
    size_t buffer_size = 0;
    size_t returned_output_size;

    if (!output || !tag)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Allocate the buffer for mbedlts_cipher_auth_encrypt_ext, which is
     * expected to output the encrypted data with the padding tag into a
     * single buffer */

    OE_CHECK(oe_safe_add_sizet(output_size, OE_GCM_TAG_SIZE, &buffer_size));

    buffer = (uint8_t*)malloc(buffer_size);
    if (!buffer)
        OE_RAISE(OE_OUT_OF_MEMORY);

    mbedtls_cipher_init(&gcm);

    switch (key_size)
    {
        case 16:
            info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
            break;
        case 32:
            info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
            break;
    }

    if (info == NULL || key_size * 8 != info->key_bitlen ||
        info->block_size != OE_GCM_TAG_SIZE)
        OE_RAISE(OE_UNSUPPORTED);

    if (mbedtls_cipher_setup(&gcm, info) ||
        mbedtls_cipher_setkey(
            &gcm, key, (int)info->key_bitlen, MBEDTLS_ENCRYPT) ||
        mbedtls_cipher_auth_encrypt_ext(
            &gcm,
            iv,
            iv_size,
            aad,
            aad_size,
            input,
            input_size,
            buffer,
            buffer_size,
            &returned_output_size,
            OE_GCM_TAG_SIZE))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Validate the returned output_size */
    if (returned_output_size != buffer_size)
        OE_RAISE(OE_CRYPTO_ERROR);

    memcpy(output, buffer, output_size);
    memcpy(tag, buffer + output_size, OE_GCM_TAG_SIZE);

done:
    free(buffer);
    buffer = NULL;

    mbedtls_cipher_free(&gcm);

    return result;
}

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
    size_t output_size,
    const uint8_t* tag)
{
    const mbedtls_cipher_info_t* info = NULL;
    mbedtls_cipher_context_t gcm;
    oe_result_t result = OE_OK;
    uint8_t* buffer = NULL;
    size_t buffer_size = 0;
    size_t returned_output_size;

    if (!input || !tag)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Allocate the buffer for mbedlts_cipher_auth_encrypt_ext, which is
     * expected to take the encrypted data with the padding tag in a single
     * buffer as an input */

    OE_CHECK(oe_safe_add_sizet(input_size, OE_GCM_TAG_SIZE, &buffer_size));

    buffer = (uint8_t*)malloc(buffer_size);
    if (!buffer)
        OE_RAISE(OE_OUT_OF_MEMORY);

    memcpy(buffer, input, input_size);
    memcpy(buffer + input_size, tag, OE_GCM_TAG_SIZE);

    mbedtls_cipher_init(&gcm);

    switch (key_size)
    {
        case 16:
            info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
            break;
        case 32:
            info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_256_GCM);
            break;
    }

    /* key size is invalid */
    if (info == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (key_size * 8 != info->key_bitlen || info->block_size != OE_GCM_TAG_SIZE)
        OE_RAISE(OE_CRYPTO_ERROR);

    if (mbedtls_cipher_setup(&gcm, info) ||
        mbedtls_cipher_setkey(
            &gcm, key, (int)info->key_bitlen, MBEDTLS_DECRYPT) ||
        mbedtls_cipher_auth_decrypt_ext(
            &gcm,
            iv,
            iv_size,
            aad,
            aad_size,
            buffer,
            buffer_size,
            output,
            output_size,
            &returned_output_size,
            OE_GCM_TAG_SIZE))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Validate the returned output_size */
    if (returned_output_size != output_size)
        OE_RAISE(OE_CRYPTO_ERROR);

done:
    free(buffer);
    buffer = NULL;

    mbedtls_cipher_free(&gcm);
    return result;
}
