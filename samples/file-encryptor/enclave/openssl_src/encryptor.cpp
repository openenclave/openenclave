// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <string.h>

#include "common/encryptor.h"
#include "common/trace.h"

struct aes_context
{
    EVP_CIPHER_CTX* ctx;
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
    int ret = 1;
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

    // init iv
    memcpy(m_operating_iv, m_header->salt, sizeof(m_header->salt));

    // initialize aes context
    m_aescontext = (struct aes_context*)malloc(sizeof(struct aes_context));

    if (m_aescontext == nullptr)
    {
        ret = 1;
        TRACE_ENCLAVE("allocate m_aescontext failed with %d", ret);
        goto exit;
    }

    if (!(m_aescontext->ctx = EVP_CIPHER_CTX_new()))
    {
        TRACE_ENCLAVE("Encryption cipher context instantiation failed");
        goto exit;
    }

    // set aes key
    if (encrypt)
    {
        if (!(ret = EVP_EncryptInit_ex(
                  m_aescontext->ctx,
                  EVP_aes_256_cbc(),
                  nullptr,
                  m_encryption_key,
                  m_operating_iv)))
        {
            TRACE_ENCLAVE("EVP_EncryptInit_ex failed with %d", ret);
            goto exit;
        }
    }
    else
    {
        if (!(ret = EVP_DecryptInit_ex(
                  m_aescontext->ctx,
                  EVP_aes_256_cbc(),
                  nullptr,
                  m_encryption_key,
                  m_operating_iv)))
        {
            TRACE_ENCLAVE("EVP_DecryptInit_ex failed with %d", ret);
            goto exit;
        }
    }

    EVP_CIPHER_CTX_set_padding(
        m_aescontext->ctx,
        0); // host application takes care of padding

    EVP_CIPHER_CTX_set_key_length(
        m_aescontext->ctx, ENCRYPTION_KEY_SIZE_IN_BYTES);

    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::encrypt_block(
    bool encrypt,
    unsigned char* input_buffer,
    unsigned char* output_buffer,
    size_t size)
{
    int ret = 1;
    int output_data_size = 0;
    int last_cipher_block_length = 0;

    if (encrypt)
    {
        if (!(ret = EVP_EncryptUpdate(
                  m_aescontext->ctx,
                  output_buffer,
                  &output_data_size,
                  input_buffer,
                  size)))
        {
            TRACE_ENCLAVE("EVP_EncryptUpdate failed with returncode %d", ret);
            goto exit;
        }

        if (!(ret = EVP_EncryptFinal_ex(
                  m_aescontext->ctx,
                  output_buffer + output_data_size,
                  &last_cipher_block_length)))
        {
            TRACE_ENCLAVE("EVP_EncryptFinal_ex failed with returncode %d", ret);
            goto exit;
        }
    }
    else
    {
        if (!(ret = EVP_DecryptUpdate(
                  m_aescontext->ctx,
                  output_buffer,
                  &output_data_size,
                  input_buffer,
                  size)))
        {
            TRACE_ENCLAVE("EVP_DecryptUpdate failed with returncode %d", ret);
            goto exit;
        }

        if (!(ret = EVP_DecryptFinal_ex(
                  m_aescontext->ctx,
                  output_buffer + output_data_size,
                  &last_cipher_block_length)))
        {
            TRACE_ENCLAVE("EVP_DecryptFinal_ex failed with returncode %d", ret);
            goto exit;
        }
    }

    ret = 0;
exit:
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
    EVP_CIPHER_CTX_free(m_aescontext->ctx);
    TRACE_ENCLAVE("ecall_dispatcher::close");
}
