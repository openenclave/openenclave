// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/evp.h>

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
    size_t output_size,
    uint8_t* tag)
{
    const EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    oe_result_t result = OE_OK;
    int len;

    OE_UNUSED(output_size);

    switch (key_size)
    {
        case 16:
            cipher = EVP_aes_128_gcm();
            break;
        case 32:
            cipher = EVP_aes_256_gcm();
            break;
    }

    /* key size is invalid */
    if (cipher == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (!EVP_EncryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_size, NULL))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (aad_size > 0 && !EVP_EncryptUpdate(ctx, NULL, &len, aad, (int)aad_size))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (input_size > 0 &&
        !EVP_EncryptUpdate(ctx, output, &len, input, (int)input_size))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!EVP_EncryptFinal_ex(ctx, output + len, &len))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_GET_TAG, OE_GCM_TAG_SIZE, tag))
        OE_RAISE(OE_CRYPTO_ERROR);

done:
    EVP_CIPHER_CTX_free(ctx);
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
    const EVP_CIPHER* cipher = NULL;
    EVP_CIPHER_CTX* ctx = NULL;
    oe_result_t result = OE_OK;
    int len;

    OE_UNUSED(output_size);

    switch (key_size)
    {
        case 16:
            cipher = EVP_aes_128_gcm();
            break;
        case 32:
            cipher = EVP_aes_256_gcm();
            break;
    }

    if (cipher == NULL)
        OE_RAISE(OE_UNSUPPORTED);

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    if (!EVP_DecryptInit_ex(ctx, cipher, NULL, NULL, NULL))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!EVP_CIPHER_CTX_ctrl(
            ctx, EVP_CTRL_AEAD_SET_TAG, OE_GCM_TAG_SIZE, (void*)tag))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_AEAD_SET_IVLEN, (int)iv_size, NULL))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!EVP_DecryptInit_ex(ctx, NULL, NULL, key, iv))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (aad_size > 0 && !EVP_DecryptUpdate(ctx, NULL, &len, aad, (int)aad_size))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (input_size > 0 &&
        !EVP_DecryptUpdate(ctx, output, &len, input, (int)input_size))
        OE_RAISE(OE_CRYPTO_ERROR);

    if (!EVP_DecryptFinal_ex(ctx, output + len, &len))
        OE_RAISE(OE_CRYPTO_ERROR);

done:
    EVP_CIPHER_CTX_free(ctx);
    return result;
}
