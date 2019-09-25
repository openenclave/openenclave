// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "encryptor.h"
#include <string.h>
#include "common.h"

ecall_dispatcher::ecall_dispatcher() : m_encrypt(true), m_header(NULL)
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

int ecall_dispatcher::initialize(
    bool encrypt,
    const char* password,
    size_t password_len,
    encryption_header_t* header)
{
    int ret = 0;
    TRACE_ENCLAVE(
        "ecall_dispatcher::initialize : %s request",
        encrypt ? "encrypting" : "decrypting");

    m_encrypt = encrypt;
    memset((void*)m_encryption_key, 0, ENCRYPTION_KEY_SIZE_IN_BYTES);

    ret = process_encryption_header(encrypt, password, password_len, header);
    if (ret != 0)
    {
        TRACE_ENCLAVE("process_encryption_header failed with %d", ret);
        goto exit;
    }

    // initialize aes context
    mbedtls_aes_init(&m_aescontext);

    // set aes key
    if (encrypt)
        ret = mbedtls_aes_setkey_enc(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);
    else
        ret = mbedtls_aes_setkey_dec(
            &m_aescontext, m_encryption_key, ENCRYPTION_KEY_SIZE);

    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_setkey_dec failed with %d", ret);
        goto exit;
    }
    // init iv
    memcpy(m_operating_iv, m_original_iv, IV_SIZE);
exit:
    return ret;
}

int ecall_dispatcher::encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char* output_buf,
    size_t size)
{
    int ret = 0;
    ret = mbedtls_aes_crypt_cbc(
        &m_aescontext,
        encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        size,           // input data length in bytes,
        m_operating_iv, // Initialization vector (updated after use)
        input_buf,
        output_buf);
    if (ret != 0)
    {
        TRACE_ENCLAVE("mbedtls_aes_crypt_cbc failed with %d", ret);
    }
    return ret;
}

void ecall_dispatcher::close()
{
    if (m_encrypt)
    {
        oe_host_free(m_header);
        m_header = NULL;
    }

    // free aes context
    mbedtls_aes_free(&m_aescontext);
    TRACE_ENCLAVE("ecall_dispatcher::close");
}
