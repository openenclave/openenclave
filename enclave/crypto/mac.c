// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/cmac.h>
#include <mbedtls/config.h>
#include <openenclave/enclave.h>

#include <openenclave/bits/mac.h>
#include <openenclave/bits/trace.h>

OE_STATIC_ASSERT(sizeof(OE_MAC) * 8 == 128);

OE_Result OE_GetMAC(
    const uint8_t* sealKey,
    uint32_t sealKeySize,
    const uint8_t* src,
    uint32_t len,
    OE_MAC* mac)
{
    OE_Result result = OE_OK;
    const mbedtls_cipher_info_t* info = NULL;

    if (mac == NULL)
        OE_THROW(OE_BUFFER_TOO_SMALL);

    if (sealKeySize != 32)
        OE_THROW(OE_INVALID_PARAMETER);

    //OE_ENSURE_ENCLAVE_INPUT(sealKey, sealKeySize);
    //OE_ENSURE_ENCLAVE_INPUT(src, len);
    //OE_ENSURE_ENCLAVE_INPUT(mac, sizeof(*mac));

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (info == NULL)
        OE_THROW(OE_CRYPTO_ERROR);

    mbedtls_cipher_cmac(info, sealKey, sealKeySize, src, len, mac->bytes);

OE_CATCH:

    return OE_OK;
}
