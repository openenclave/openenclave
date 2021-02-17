// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <string.h>

#include "common/trace.h"
#include "encryptor.h"

ecall_dispatcher::ecall_dispatcher() : m_encrypt(true), m_header(NULL)
{
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

    if (header == NULL)
    {
        TRACE_ENCLAVE("initialize() failed as NULL was passed in place of "
                      "(encryption_header_t *)");
        goto exit;
    }

    m_password = std::string(password, password + password_len);
    m_encrypt = encrypt;
    m_header = header;

    memset((void*)m_encryption_key, 0, ENCRYPTION_KEY_SIZE_IN_BYTES);

    ret = process_encryption_header(header);
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
    memcpy(m_operating_iv, m_header->salt, IV_SIZE);
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
