// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/cipher.h>

#include <openenclave/internal/crypto/gcm.h>
#include <openenclave/internal/raise.h>

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
    uint8_t* tag)
{
    const mbedtls_cipher_info_t* info = NULL;
    mbedtls_cipher_context_t gcm;
    oe_result_t result = OE_OK;
    size_t size;

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

    if (info == NULL || key_size * 8 != info->key_bitlen)
        return OE_UNSUPPORTED;

    if (mbedtls_cipher_setup(&gcm, info) ||
        mbedtls_cipher_setkey(
            &gcm, key, (int)info->key_bitlen, MBEDTLS_ENCRYPT) ||
        mbedtls_cipher_auth_encrypt(
            &gcm,
            iv,
            iv_size,
            aad,
            aad_size,
            input,
            input_size,
            output,
            &size,
            tag,
            info->block_size))
        result = OE_CRYPTO_ERROR;

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
    const uint8_t* tag)
{
    const mbedtls_cipher_info_t* info;
    mbedtls_cipher_context_t gcm;
    oe_result_t result = OE_OK;
    size_t size;

    mbedtls_cipher_init(&gcm);

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_GCM);
    if (info == NULL)
        return OE_CRYPTO_ERROR;

    if (key_size * 8 != info->key_bitlen)
        return OE_UNSUPPORTED;

    if (mbedtls_cipher_setup(&gcm, info) ||
        mbedtls_cipher_setkey(
            &gcm, key, (int)info->key_bitlen, MBEDTLS_DECRYPT) ||
        mbedtls_cipher_auth_decrypt(
            &gcm,
            iv,
            iv_size,
            aad,
            aad_size,
            input,
            input_size,
            output,
            &size,
            tag,
            info->block_size))
        result = OE_CRYPTO_ERROR;

    mbedtls_cipher_free(&gcm);
    return result;
}
