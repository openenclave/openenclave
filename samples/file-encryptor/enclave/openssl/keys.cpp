// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/rand.h>
#include <string.h>
#include "../common/trace.h"
#include "encryptor.h"

#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false
#define SALT_SIZE_IN_BYTES 16 // Length of salt size

void ecall_dispatcher::dump_data(
    const char* name,
    unsigned char* data,
    size_t data_size)
{
    TRACE_ENCLAVE("Data name: %s", name);
    for (size_t i = 0; i < data_size; i++)
    {
        TRACE_ENCLAVE("[%ld]-0x%02X", i, data[i]);
    }
    TRACE_ENCLAVE("\n");
}

// Compute the sha256 hash of given data.
int ecall_dispatcher::Sha256(
    const uint8_t* data,
    size_t data_size,
    uint8_t sha256[32])
{
    int ret = -1;
    unsigned int sha_length_in_bytes = 32;
    EVP_MD_CTX* mdctx;

    if ((mdctx = EVP_MD_CTX_new()) == NULL)
    {
        TRACE_ENCLAVE("Message digest context instantiation failed");
        goto exit;
    }

    if (!EVP_DigestInit_ex(mdctx, EVP_sha256(), NULL))
    {
        TRACE_ENCLAVE(
            "Message digest context initialization to SHA-256 failed");
        goto exit;
    }

    if (!EVP_DigestUpdate(mdctx, data, data_size))
    {
        TRACE_ENCLAVE("Message digest context update to input data failed");
        goto exit;
    }

    if (!EVP_DigestFinal_ex(mdctx, sha256, &sha_length_in_bytes))
    {
        TRACE_ENCLAVE("Message Digest Final failed");
        goto exit;
    }

    ret = 0;
exit:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

// This routine uses the openssl library to derive an AES key from the input
// password and produce a password based key. Note : A set of hardcoded salt
// values are used here to simplify this sample, which caused
// this routine to return the same key when taking the same password. This saves
// the sample from having to write salt values to the encryption header. In a
// real world application, randomly generated salt values are recommended.
int ecall_dispatcher::generate_password_key(
    const char* password,
    unsigned char* key,
    unsigned int key_len)
{
    int ret = 0;
    unsigned char salt[SALT_SIZE_IN_BYTES] = {0xb2,
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
    if (PKCS5_PBKDF2_HMAC(
            (const char*)password,
            strlen((const char*)password),
            salt,
            SALT_SIZE_IN_BYTES,
            100000,
            EVP_sha256(),
            key_len,
            key) == 0)
    {
        TRACE_ENCLAVE("Key generation from password using method "
                      "PKCS5_PBKDF2_HMAC failed");
        ret = -1;
        goto exit;
    }
exit:
    return ret;
}

// Generate an encryption key: this is the key used to encrypt data
int ecall_dispatcher::generate_encryption_key(
    unsigned char* key,
    unsigned int key_len)
{
    TRACE_ENCLAVE("generating encryption key");
    int ret = 0;
    memset(key, 0, key_len);
    if (!RAND_bytes(key, key_len))
    {
        TRACE_ENCLAVE("generating random key using RAND_bytes failed");
        ret = -1;
        goto exit;
    }
exit:
    return ret;
}

// The encryption key is encrypted before it was written back to the encryption
// header as part of the encryption metadata. Note: using fixed initialization
// vector (iv) is good enough because it's used only for the purpose of
// encrypting encryption key, just once.
int ecall_dispatcher::cipher_encryption_key(
    bool encrypt,
    unsigned char* input_data,
    unsigned int input_data_size,
    unsigned char* encrypt_key,
    unsigned char* output_data,
    int output_data_size)
{
    int ret = -1;
    int last_cipher_block_length = 0;
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

    TRACE_ENCLAVE(
        "cipher_encryption_key: %s", encrypt ? "encrypting" : "decrypting");

    EVP_CIPHER_CTX* ctx;

    /* Create and initialize the context */
    if (!(ctx = EVP_CIPHER_CTX_new()))
    {
        TRACE_ENCLAVE(
            "Context instantiation for key encryption/decryption failed");
        goto exit;
    }

    if (encrypt)
    {
        if (!EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encrypt_key, iv))
        {
            TRACE_ENCLAVE("Context initialization for key encryption failed");
            goto exit;
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP_CIPHER_CTX_set_key_length(ctx, ENCRYPTION_KEY_SIZE_IN_BYTES);

        if (!EVP_EncryptUpdate(
                ctx,
                output_data,
                &output_data_size,
                input_data,
                input_data_size))
        {
            TRACE_ENCLAVE("Encryption update for key encryption failed");
            goto exit;
        }

        if (!EVP_EncryptFinal_ex(
                ctx, output_data + output_data_size, &last_cipher_block_length))
        {
            TRACE_ENCLAVE("Encryption final update / padding check for key "
                          "encryption failed");
            goto exit;
        }
    }
    else
    {
        if (!EVP_DecryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, encrypt_key, iv))
        {
            TRACE_ENCLAVE("Context initialization for key decryption failed");
            goto exit;
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP_CIPHER_CTX_set_key_length(ctx, ENCRYPTION_KEY_SIZE_IN_BYTES);

        if (!EVP_DecryptUpdate(
                ctx,
                output_data,
                &output_data_size,
                input_data,
                input_data_size))
        {
            TRACE_ENCLAVE("Decryption update for key decryption failed");
            goto exit;
        }

        if (!EVP_DecryptFinal_ex(
                ctx, output_data + output_data_size, &last_cipher_block_length))
        {
            TRACE_ENCLAVE("Decryption final update / padding check for key "
                          "decryption failed");
            goto exit;
        }
    }

    ret = 0;
exit:
    EVP_CIPHER_CTX_free(ctx);
    return ret;
}

// For an encryption operation, the encryptor creates encryption metadata for
// writing back to the encryption header, which includes the following fields:
// digest: a hash value of the password
// key: encrypted version of the encryption key
//
// Operations involves the following operations:
//  1)derive a key from the password
//  2)produce a encryption key
//  3)generate a digest for the password
//  4)encrypt the encryption key with a password key
//
int ecall_dispatcher::prepare_encryption_header(
    encryption_header_t* header,
    string password)
{
    int ret = 0;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES]; // password derived key
    unsigned char
        password_key[ENCRYPTION_KEY_SIZE_IN_BYTES]; // encrypted encryption key
    unsigned char encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES];

    TRACE_ENCLAVE("prepare_encryption_header");
    // derive a key from the password using PBDKF2
    ret = generate_password_key(
        password.c_str(), password_key, ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("password_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            TRACE_ENCLAVE(
                "password_key[%d] =0x%02x", i, (unsigned int)(password_key[i]));
        goto exit;
    }

    // produce a encryption key
    ret = generate_encryption_key(
        (unsigned char*)m_encryption_key, ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Enclave: m_encryption_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            TRACE_ENCLAVE(
                "m_encryption_key[%d] =0x%02x", i, m_encryption_key[i]);
        goto exit;
    }

    // generate a digest for the password
    TRACE_ENCLAVE("generate a digest for the password");
    ret = Sha256((const uint8_t*)password.c_str(), password.length(), digest);
    if (ret)
    {
        TRACE_ENCLAVE("Sha256 failed with %d", ret);
        goto exit;
    }
    memcpy(header->digest, digest, ENCRYPTION_KEY_SIZE_IN_BYTES);

    // encrypt the encryption key with a password key
    TRACE_ENCLAVE("encrypt the encryption key with a psswd key");
    ret = cipher_encryption_key(
        ENCRYPT_OPERATION,
        m_encryption_key,
        ENCRYPTION_KEY_SIZE_IN_BYTES,
        password_key,
        encrypted_key,
        ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("EncryptEncryptionKey failed with [%d]", ret);
        goto exit;
    }
    memcpy(header->encrypted_key, encrypted_key, ENCRYPTION_KEY_SIZE_IN_BYTES);
exit:
    return ret;
}

// Parse an input header for validating the password and getting the encryption
// key in preparation for decryption/encryption operations
//  1)Check password by comparing their digests
//  2)reproduce a encryption key from the password
//  3)decrypt the encryption key with a password key
int ecall_dispatcher::parse_encryption_header(
    encryption_header_t* header,
    string password)
{
    int ret = 0;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char password_key[ENCRYPTION_KEY_SIZE_IN_BYTES];

    // check password by comparing their digests
    ret =
        Sha256((const uint8_t*)m_password.c_str(), m_password.length(), digest);
    if (ret)
    {
        TRACE_ENCLAVE("Sha256 failed with %d", ret);
        goto exit;
    }

    if (memcmp(header->digest, digest, HASH_VALUE_SIZE_IN_BYTES) != 0)
    {
        TRACE_ENCLAVE("incorrect password");
        ret = 1;
        goto exit;
    }

    // derive a key from the password using PBDKF2
    ret = generate_password_key(
        password.c_str(), password_key, ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("generate_password_key failed with %d", ret);
        goto exit;
    }
    // decrypt the "encrypted encryption key" using the password key
    ret = cipher_encryption_key(
        DECRYPT_OPERATION,
        header->encrypted_key,
        ENCRYPTION_KEY_SIZE_IN_BYTES,
        password_key,
        (unsigned char*)m_encryption_key,
        ENCRYPTION_KEY_SIZE_IN_BYTES);
    if (ret != 0)
    {
        TRACE_ENCLAVE("Enclave: m_encryption_key");
        for (unsigned int i = 0; i < ENCRYPTION_KEY_SIZE_IN_BYTES; i++)
            TRACE_ENCLAVE(
                "m_encryption_key[%d] =0x%02x", i, m_encryption_key[i]);
        goto exit;
    }
exit:
    return ret;
}

int ecall_dispatcher::process_encryption_header(
    bool encrypt,
    const char* password,
    size_t password_len,
    encryption_header_t* header)
{
    int ret = 0;

    m_password = std::string(password, password + password_len);
    m_encrypt = encrypt;
    m_header = header;

    if (m_encrypt)
    {
        // allocate host memory for the header and it will be returned back to
        // the host
        m_header =
            (encryption_header_t*)oe_host_malloc(sizeof(encryption_header_t));
        if (m_header == NULL)
        {
            ret = 1;
            goto exit;
        }

        TRACE_ENCLAVE("prepare_encryption_header call");
        ret = prepare_encryption_header(m_header, m_password);
        if (ret != 0)
        {
            TRACE_ENCLAVE("prepare_encryption_header failed with %d", ret);
            goto exit;
        }
        memcpy(header, m_header, sizeof(encryption_header_t));
    }
    else
    {
        ret = parse_encryption_header(m_header, m_password);
        if (ret != 0)
        {
            TRACE_ENCLAVE("parse_encryption_header failed with %d", ret);
            goto exit;
        }
    }
exit:
    return ret;
}
