// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "encryptor.h"
#include <string.h>
#include "../common/trace.h"

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
    int ret = -1;
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

    if (!(m_encryption_cipher_ctx = EVP_CIPHER_CTX_new()))
    {
        TRACE_ENCLAVE("Encryption cipher context instantiation failed");
        goto exit;
    }

    if (!EVP_EncryptInit_ex(
            m_encryption_cipher_ctx,
            EVP_aes_256_cbc(),
            NULL,
            m_encryption_key,
            m_original_iv))
    {
        TRACE_ENCLAVE("Encryption cipher context instantiation failed");
        goto exit;
    }

    EVP_CIPHER_CTX_set_padding(
        m_encryption_cipher_ctx,
        0); // host application should take care of padding

    EVP_CIPHER_CTX_set_key_length(
        m_encryption_cipher_ctx, ENCRYPTION_KEY_SIZE_IN_BYTES);

    if (!(m_decryption_cipher_ctx = EVP_CIPHER_CTX_new()))
    {
        TRACE_ENCLAVE("Encryption cipher context instantiation failed");
        goto exit;
    }

    if (!EVP_DecryptInit_ex(
            m_decryption_cipher_ctx,
            EVP_aes_256_cbc(),
            NULL,
            m_encryption_key,
            m_original_iv))
    {
        TRACE_ENCLAVE("Encryption cipher context instantiation failed");
        goto exit;
    }

    EVP_CIPHER_CTX_set_padding(
        m_decryption_cipher_ctx,
        0); // host application should take care of padding

    EVP_CIPHER_CTX_set_key_length(
        m_decryption_cipher_ctx, ENCRYPTION_KEY_SIZE_IN_BYTES);

    ret = 0;

exit:
    return ret;
}

int ecall_dispatcher::encrypt_block(
    bool encrypt,
    unsigned char* input_buf,
    unsigned char* output_buf,
    size_t input_size)
{
    int ret = -1;
    int output_data_size = 0;
    int last_cipher_block_length = 0;

    if (m_encrypt)
    {
        if (!EVP_EncryptUpdate(
                m_encryption_cipher_ctx,
                output_buf,
                &output_data_size,
                input_buf,
                input_size))
        {
            TRACE_ENCLAVE("Block encryption update failed");
            goto exit;
        }

        if (!EVP_EncryptFinal_ex(
                m_encryption_cipher_ctx,
                output_buf + output_data_size,
                &last_cipher_block_length))
        {
            TRACE_ENCLAVE("Block encryption final padding check failed");
            goto exit;
        }
    }
    else
    {
        if (!EVP_DecryptUpdate(
                m_decryption_cipher_ctx,
                output_buf,
                &output_data_size,
                input_buf,
                input_size))
        {
            TRACE_ENCLAVE("Block decryption update failed");
            goto exit;
        }

        if (!EVP_DecryptFinal_ex(
                m_decryption_cipher_ctx,
                output_buf + output_data_size,
                &last_cipher_block_length))
        {
            TRACE_ENCLAVE("Block decryption final padding check failed");
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
        m_header = NULL;
    }

    EVP_CIPHER_CTX_free(m_encryption_cipher_ctx);
    EVP_CIPHER_CTX_free(m_decryption_cipher_ctx);
    TRACE_ENCLAVE("ecall_dispatcher::close");
}
