// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/cmac.h>
#include <mbedtls/config.h>
#include <openenclave/enclave.h>

#include <openenclave/bits/mac.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sgxtypes.h>

OE_STATIC_ASSERT(sizeof(OE_MAC) * 8 == 128);

OE_Result OE_GetMAC(
    const uint8_t* key,
    uint32_t keySize,
    const uint8_t* src,
    uint32_t len,
    OE_MAC* mac)
{
    OE_Result result = OE_OK;
    const mbedtls_cipher_info_t* info = NULL;
    
    if (mac == NULL)
        OE_RAISE(OE_BUFFER_TOO_SMALL);

    if (keySize != sizeof(SGX_Key))
        OE_RAISE(OE_INVALID_PARAMETER);

    info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_ECB);
    if (info == NULL)
        OE_RAISE(OE_FAILURE);

    mbedtls_cipher_cmac(info, key, keySize * 8, src, len, mac->bytes);

done:
    return result;
}
