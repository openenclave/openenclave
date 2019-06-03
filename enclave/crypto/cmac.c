// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/cmac.h>
#include <mbedtls/pk.h>

#include <openenclave/enclave.h>
#include <openenclave/internal/crypto/cmac.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

oe_result_t oe_aes_cmac_sign(
    const uint8_t* key,
    size_t key_size,
    const uint8_t* message,
    size_t message_length,
    oe_aes_cmac_t* aes_cmac)
{
    oe_result_t result = OE_UNEXPECTED;
    const mbedtls_cipher_info_t* info = NULL;
    size_t key_size_bits = key_size * 8;

    if (aes_cmac == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (key_size_bits != 128)
        OE_RAISE(OE_UNSUPPORTED);

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (info == NULL)
        OE_RAISE(OE_CRYPTO_ERROR);

    oe_secure_zero_fill(aes_cmac->impl, sizeof(*aes_cmac));

    if (mbedtls_cipher_cmac(
            info,
            key,
            key_size_bits,
            message,
            message_length,
            (uint8_t*)aes_cmac->impl) != 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    result = OE_OK;

done:
    return result;
}
