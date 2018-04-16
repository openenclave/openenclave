// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/aes.h>
#include <mbedtls/error.h>
#include <mbedtls/sha256.h>
#include <openenclave/enclave.h>
#include <stdio.h>
#include <string.h>
#include "../args.h"

OE_ECALL void Hash(void* args_)
{
    HashArgs* args = (HashArgs*)args_;

    if (!args || !args->data)
        return;

    memset(args->hash, 0, sizeof(args->hash));
    mbedtls_sha256_context ctx;
    mbedtls_sha256_init(&ctx);
    mbedtls_sha256_starts(&ctx, 0);
    mbedtls_sha256_update(&ctx, args->data, args->size);
    mbedtls_sha256_finish(&ctx, args->hash);
}

OE_ECALL void AesEncrypt(void* args_)
{
    AesArgs* args = (AesArgs*)args_;

    if (!args || !args->plaintext || !args->encrypted)
        return;

    memset(args->encrypted, 0, sizeof(args->encrypted));

    // Define arbitrary test key to produce expected encrypted output
    uint8_t key[32] = {0x53, 0x88, 0x2d, 0xed, 0x42, 0x0d, 0x92, 0x44,
                       0xc0, 0xc8, 0x66, 0x53, 0xdd, 0x6a, 0x18, 0x00,
                       0xf5, 0x63, 0x21, 0x9b, 0x11, 0x1d, 0x37, 0xd3,
                       0xa1, 0xb8, 0x50, 0xae, 0x08, 0xe3, 0xb0, 0xf7};

    mbedtls_aes_context aes;
    uint8_t iv[16] = {0};
    char errstring[256] = {0};

    int err = mbedtls_aes_setkey_enc(&aes, key, 256);
    if (err)
    {
        mbedtls_strerror(err, errstring, sizeof(errstring));
        OE_HostPrintf("setkey error: %x (%s)\n", err, errstring);
        return;
    }

    err = mbedtls_aes_crypt_cbc(
        &aes, MBEDTLS_AES_ENCRYPT, 128, iv, args->plaintext, args->encrypted);
    if (err)
    {
        mbedtls_strerror(err, errstring, sizeof(errstring));
        OE_HostPrintf("mbedtls_aes_crypt_cbc error: %x (%s)\n", err, errstring);
    }
}