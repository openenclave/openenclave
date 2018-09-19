// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "encryptor.h"
#include <string.h>
#include "common.h"

ECallDispatcher::ECallDispatcher() : m_bEncrypt(true), m_pHeader(NULL)
{
    unsigned char iv[IV_SIZE] = {0xb2,
                                 0x4b,
                                 0xf2,
                                 0xf7,
                                 0x7a,
                                 0xc5,
                                 0xec,
                                 0x0c,
                                 0x5e,
                                 0x1f,
                                 0x4d,
                                 0xc1,
                                 0xae,
                                 0x46,
                                 0x5e,
                                 0x75};
    memcpy(m_original_iv, iv, IV_SIZE);
}

void ECallDispatcher::Initialize(EncryptInitializeArgs* args)
{
    int ret = 0;
    ENC_DEBUG_PRINTF(
        "ECallDispatcher::Initialize : %s request",
        args->bEncrypt ? "encrypting" : "decrypting");

    ret = processEncryptionHeader(args);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("processEncryptionHeader failed with %d", ret);
        goto exit;
    }

    // initialize aes context
    mbedtls_aes_init(&m_aescontext);

    // set aes key
    if (args->bEncrypt)
        ret = mbedtls_aes_setkey_enc(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);
    else
        ret = mbedtls_aes_setkey_dec(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);

    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_aes_setkey_dec failed with %d", ret);
        goto exit;
    }
    // init iv
    memcpy(m_operating_iv, m_original_iv, IV_SIZE);
exit:
    return;
}

void ECallDispatcher::EncryptBlock(EncryptBlockArgs* args)
{
    int ret = 0;
    unsigned char* inputbuf = args->inputbuf;
    unsigned char* outputbuf = args->outputbuf;
    unsigned int size = args->size;

    ret = mbedtls_aes_crypt_cbc(
        &m_aescontext,
        (args->bEncrypt) ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        size,           // input data length in bytes,
        m_operating_iv, // Initialization vector (updated after use)
        inputbuf,
        outputbuf);
    if (ret != 0)
    {
        ENC_DEBUG_PRINTF("mbedtls_aes_crypt_cbc failed with %d", ret);
    }
}

void ECallDispatcher::close(CloseEncryptorArgs* args)
{
    if (m_bEncrypt)
    {
        oe_host_free(m_pHeader);
        m_pHeader = NULL;
    }

    // free aes context
    mbedtls_aes_free(&m_aescontext);
    ENC_DEBUG_PRINTF("ECallDispatcher::close");
}
