// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/cmac.h>
#include <openssl/evp.h>

#include <openenclave/internal/crypto/cmac.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#if OPENSSL_VERSION_NUMBER >= 0x30000000L
#include <openssl/core_names.h>
#endif

#if OPENSSL_VERSION_NUMBER < 0x30000000L
oe_result_t oe_aes_cmac_sign(
    const uint8_t* key,
    size_t key_size,
    const uint8_t* message,
    size_t message_length,
    oe_aes_cmac_t* aes_cmac)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t key_size_bits = key_size * 8;
    size_t final_size = sizeof(oe_aes_cmac_t);
    CMAC_CTX* ctx = NULL;

    if (aes_cmac == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (key == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (message == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (key_size_bits != 128)
        OE_RAISE(OE_UNSUPPORTED);

    oe_secure_zero_fill(aes_cmac->impl, sizeof(*aes_cmac));

    ctx = CMAC_CTX_new();
    if (ctx == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    CMAC_Init(ctx, key, key_size, EVP_aes_128_cbc(), NULL);
    CMAC_Update(ctx, message, message_length);
    CMAC_Final(ctx, (unsigned char*)aes_cmac->impl, &final_size);

    result = OE_OK;

done:
    if (ctx)
        CMAC_CTX_free(ctx);

    return result;
}
#else
oe_result_t oe_aes_cmac_sign(
    const uint8_t* key,
    size_t key_size,
    const uint8_t* message,
    size_t message_length,
    oe_aes_cmac_t* aes_cmac)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t key_size_bits = key_size * 8;
    size_t final_size = sizeof(oe_aes_cmac_t);
    EVP_MAC_CTX* ctx = NULL;
    EVP_MAC* mac = NULL;
    OSSL_PARAM params[3];

    if (key == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (message == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (aes_cmac == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (key_size_bits != 128)
        OE_RAISE(OE_UNSUPPORTED);

    oe_secure_zero_fill(aes_cmac->impl, sizeof(*aes_cmac));

    mac = EVP_MAC_fetch(NULL, OSSL_MAC_NAME_CMAC, NULL);
    if (!mac)
        OE_RAISE(OE_CRYPTO_ERROR);

    ctx = EVP_MAC_CTX_new(mac);
    if (ctx == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    params[0] = OSSL_PARAM_construct_octet_string(
        OSSL_MAC_PARAM_KEY, (void*)key, key_size);
    params[1] = OSSL_PARAM_construct_utf8_string(
        OSSL_MAC_PARAM_CIPHER, "AES-128-CBC", 0);
    params[2] = OSSL_PARAM_construct_end();

    if (!EVP_MAC_init(ctx, NULL, 0, params))
        OE_RAISE(OE_CRYPTO_ERROR);
    if (!EVP_MAC_update(ctx, message, message_length))
        OE_RAISE(OE_CRYPTO_ERROR);
    if (!EVP_MAC_final(
            ctx,
            (unsigned char*)aes_cmac->impl,
            &final_size,
            sizeof(oe_aes_cmac_t)))
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    if (ctx)
        EVP_MAC_CTX_free(ctx);
    if (mac)
        EVP_MAC_free(mac);

    return result;
}
#endif
