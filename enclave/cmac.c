// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/cmac.h>
#include <mbedtls/config.h>
#include <openenclave/enclave.h>

#include <openenclave/bits/cmac.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sgxtypes.h>

OE_Result OE_Get_AES_CMAC(
    const uint8_t* key,
    uint32_t keySize,
    const uint8_t* message,
    uint32_t messageLength,
    uint8_t* cmac)
{
    OE_Result result = OE_UNEXPECTED;
    const mbedtls_cipher_info_t* info = NULL;
    uint32_t keySizeBits = keySize * 8;

    if (cmac == NULL)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (keySize != 128)
        OE_RAISE(OE_UNSUPPORTED);

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (info == NULL)
        OE_RAISE(OE_FAILURE);

    if (mbedtls_cipher_cmac(info, key, keySizeBits, message, messageLength, cmac) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:
    return result;
}
