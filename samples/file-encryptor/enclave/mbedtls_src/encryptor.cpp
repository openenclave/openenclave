// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <mbedtls/aes.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <string.h>

#include "common/encryptor.h"
#include "common/trace.h"

struct aes_context
{
    mbedtls_aes_context ctx;
};

ecall_dispatcher::ecall_dispatcher() : m_encrypt(true), m_header(nullptr)
{
}

int ecall_dispatcher::initialize(
    bool encrypt,
    const char* password,
    size_t password_size,
    encryption_header_t* header)
{
    int ret = 0;
    TRACE_ENCLAVE(
        "ecall_dispatcher::initialize : %s request",
        encrypt ? "encrypting" : "decrypting");

    if (header == nullptr)
    {
        TRACE_ENCLAVE("initialize() failed as nullptr was passed in place of "
                      "(encryption_header_t *)");
        goto exit;
    }

    m_password = string(password, password + password_size);
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
    m_aescontext = (struct aes_context*)malloc(sizeof(struct aes_context));
    if (m_aescontext == nullptr)
    {
        ret = 1;
        TRACE_ENCLAVE("allocate m_aescontext failed with %d", ret);
        goto exit;
    }

    mbedtls_aes_init(&(m_aescontext->ctx));

    // set aes key
    if (encrypt)
        ret = mbedtls_aes_setkey_enc(
            &(m_aescontext->ctx), m_encryption_key, ENCRYPTION_KEY_SIZE);
    else
        ret = mbedtls_aes_setkey_dec(
            &(m_aescontext->ctx), m_encryption_key, ENCRYPTION_KEY_SIZE);

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
    unsigned char* input_buffer,
    unsigned char* output_buffer,
    size_t size)
{
    int ret = 0;

    ret = mbedtls_aes_crypt_cbc(
        &(m_aescontext->ctx),
        encrypt ? MBEDTLS_AES_ENCRYPT : MBEDTLS_AES_DECRYPT,
        size,           // input data length in bytes,
        m_operating_iv, // Initialization vector (updated after use)
        input_buffer,
        output_buffer);
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
        m_header = nullptr;
    }

    // free aes context
    mbedtls_aes_free(&(m_aescontext->ctx));
    TRACE_ENCLAVE("ecall_dispatcher::close");
}
