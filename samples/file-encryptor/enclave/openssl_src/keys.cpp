// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <string.h>

#include "common/encryptor.h"
#include "common/trace.h"

#define ENCRYPT_OPERATION true
#define DECRYPT_OPERATION false

// Compute the sha256 hash of given data.
int ecall_dispatcher::Sha256(
    const uint8_t* data,
    size_t data_size,
    uint8_t sha256[HASH_VALUE_SIZE_IN_BYTES])
{
    int ret = 1;
    unsigned int sha_length_in_bytes = HASH_VALUE_SIZE_IN_BYTES;
    EVP_MD_CTX* mdctx;

    if ((mdctx = EVP_MD_CTX_new()) == nullptr)
    {
        TRACE_ENCLAVE("EVP_MD_CTX_new failed");
        goto exit;
    }

    if (!(ret = EVP_DigestInit_ex(mdctx, EVP_sha256(), nullptr)))
    {
        TRACE_ENCLAVE(
            "EVP_DigestInit_ex SHA-256 failed with returncode %d", ret);
        goto exit;
    }

    if (!(ret = EVP_DigestUpdate(mdctx, data, data_size)))
    {
        TRACE_ENCLAVE("EVP_DigestUpdate failed with returncode %d", ret);
        goto exit;
    }

    if (!(ret = EVP_DigestFinal_ex(mdctx, sha256, &sha_length_in_bytes)))
    {
        TRACE_ENCLAVE("EVP_DigestFinal_ex failed with return code %d", ret);
        goto exit;
    }

    ret = 0;
exit:
    EVP_MD_CTX_free(mdctx);
    return ret;
}

// This routine uses the openssl library to derive an AES key from the input
// password and produce a password based key.
int ecall_dispatcher::generate_password_key(
    const char* password,
    unsigned char* salt,
    unsigned char* key,
    unsigned int key_size)
{
    int ret = 1;

    if (PKCS5_PBKDF2_HMAC(
            (const char*)password,              // passwd
            (int)strlen((const char*)password), // passwd length
            salt,                               // salt
            SALT_SIZE_IN_BYTES,                 // salt length
            100000,                             // iteration count
            EVP_sha256(),                       // digest function
            key_size,                           // key length
            key) == 0)                          // key
    {
        TRACE_ENCLAVE("Key generation from password using method "
                      "PKCS5_PBKDF2_HMAC failed");
        goto exit;
    }

    ret = 0;
exit:
    return ret;
}

// Generate an encryption key: this is the key used to encrypt data
int ecall_dispatcher::generate_encryption_key(
    unsigned char* key,
    unsigned int key_size)
{
    TRACE_ENCLAVE("generating encryption key");
    int ret = 1;

    memset(key, 0, key_size);

    if (!(ret = RAND_bytes(key, key_size)))
    {
        TRACE_ENCLAVE("RAND_bytes failed with return code %d", ret);
        goto exit;
    }

    ret = 0;
exit:
    return ret;
}

// The encryption key is encrypted before it is written back to the encryption
// header as part of the encryption metadata.
int ecall_dispatcher::cipher_encryption_key(
    bool encrypt,
    unsigned char* input_data,
    unsigned int input_data_size,
    unsigned char* encrypt_key,
    unsigned char* iv,
    unsigned char* output_data,
    unsigned int output_data_size)
{
    int ret = 1;
    int last_cipher_block_length = 0;

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
        if (!(ret = EVP_EncryptInit_ex(
                  ctx, EVP_aes_256_cbc(), nullptr, encrypt_key, iv)))
        {
            TRACE_ENCLAVE("EVP_EncryptInit_ex failed with return code %d", ret);
            goto exit;
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP_CIPHER_CTX_set_key_length(ctx, ENCRYPTION_KEY_SIZE_IN_BYTES);

        if (!(ret = EVP_EncryptUpdate(
                  ctx,
                  output_data,
                  (int*)&output_data_size,
                  input_data,
                  (int)input_data_size)))
        {
            TRACE_ENCLAVE("EVP_EncryptUpdate failed return code %d", ret);
            goto exit;
        }

        if (!(ret = EVP_EncryptFinal_ex(
                  ctx,
                  output_data + output_data_size,
                  &last_cipher_block_length)))
        {
            TRACE_ENCLAVE(
                "EVP_EncryptFinal_ex failed with return code %d", ret);
            goto exit;
        }
    }
    else
    {
        if (!(ret = EVP_DecryptInit_ex(
                  ctx, EVP_aes_256_cbc(), nullptr, encrypt_key, iv)))
        {
            TRACE_ENCLAVE("EVP_DecryptInit_ex failed with return code %d", ret);
            goto exit;
        }

        EVP_CIPHER_CTX_set_padding(ctx, 0);
        EVP_CIPHER_CTX_set_key_length(ctx, ENCRYPTION_KEY_SIZE_IN_BYTES);

        if (!(ret = EVP_DecryptUpdate(
                  ctx,
                  output_data,
                  (int*)&output_data_size,
                  input_data,
                  (int)input_data_size)))
        {
            TRACE_ENCLAVE("EVP_DecryptUpdate failed with return code %d", ret);
            goto exit;
        }

        if (!(ret = EVP_DecryptFinal_ex(
                  ctx,
                  output_data + output_data_size,
                  &last_cipher_block_length)))
        {
            TRACE_ENCLAVE("EVP_DecryptFinal_ex failedwith return code %d", ret);
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
    int ret = 1;
    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES]; // sha256 digest of password
    unsigned char
        password_key[ENCRYPTION_KEY_SIZE_IN_BYTES]; // password generated key,
                                                    // used to encrypt
                                                    // encryption_key using
                                                    // AES256-CBC
    unsigned char
        encrypted_key[ENCRYPTION_KEY_SIZE_IN_BYTES]; // encrypted encryption_key
                                                     // using AES256-CBC
    unsigned char salt[SALT_SIZE_IN_BYTES];
    const char seed[] = "file_encryptor_sample";

    if (header == nullptr)
    {
        TRACE_ENCLAVE("prepare_encryption_header() failed with null argument"
                      " for encryption_header_t*");
        goto exit;
    }

    TRACE_ENCLAVE("prepare_encryption_header");

    // Generate random salt
    if (!(ret = RAND_bytes(salt, sizeof(salt))))
    {
        TRACE_ENCLAVE("RAND_bytes failed with return code %d", ret);
        goto exit;
    }
    memcpy(header->salt, salt, sizeof(salt));

    // derive a key from the password using PBDKF2
    ret = generate_password_key(
        password.c_str(), salt, password_key, sizeof(password_key));
    if (ret != 0)
    {
        TRACE_ENCLAVE("password_key");
        for (unsigned int i = 0; i < sizeof(password_key); i++)
            TRACE_ENCLAVE(
                "password_key[%d] =0x%02x", i, (unsigned int)(password_key[i]));
        goto exit;
    }

    // produce a encryption key
    TRACE_ENCLAVE("produce a encryption key");
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

    memcpy(header->digest, digest, sizeof(digest));

    // encrypt the encryption key with a password key
    TRACE_ENCLAVE("encrypt the encryption key with a password key");
    ret = cipher_encryption_key(
        ENCRYPT_OPERATION,
        m_encryption_key,
        ENCRYPTION_KEY_SIZE_IN_BYTES,
        password_key,
        salt, // iv for encryption, decryption. In this sample we use
              // the salt in encryption header as iv.
        encrypted_key,
        sizeof(encrypted_key));
    if (ret != 0)
    {
        TRACE_ENCLAVE("EncryptEncryptionKey failed with [%d]", ret);
        goto exit;
    }
    memcpy(header->encrypted_key, encrypted_key, sizeof(encrypted_key));

    TRACE_ENCLAVE("Done with prepare_encryption_header successfully.");
    ret = 0;
exit:
    return ret;
}

// Parse an input header for validating the password and getting the encryption
// key in preparation for decryption/encryption operations
//  1)Check password by comparing their digests
//  2)reproduce a password key from the password
//  3)decrypt the encryption key with a password key
int ecall_dispatcher::parse_encryption_header(
    encryption_header_t* header,
    string password)
{
    int ret = 1;
    if (header == nullptr)
    {
        TRACE_ENCLAVE("parse_encryption_header() failed with a null argument"
                      " for encryption_header_t*");
        goto exit;
    }

    unsigned char digest[HASH_VALUE_SIZE_IN_BYTES];
    unsigned char password_key[ENCRYPTION_KEY_SIZE_IN_BYTES];
    unsigned char salt[SALT_SIZE_IN_BYTES];

    // check password by comparing their digests
    ret =
        Sha256((const uint8_t*)m_password.c_str(), m_password.length(), digest);
    if (ret)
    {
        TRACE_ENCLAVE("Sha256 failed with %d", ret);
        goto exit;
    }

    if (memcmp(header->digest, digest, sizeof(digest)) != 0)
    {
        TRACE_ENCLAVE("incorrect password");
        ret = 1;
        goto exit;
    }

    memcpy(salt, header->salt, sizeof(salt));

    // derive a key from the password using PBDKF2
    ret = generate_password_key(
        password.c_str(), salt, password_key, sizeof(password_key));
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
        salt, // iv for encryption, decryption. In this sample we use
              // the salt in encryption header as iv.
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

    ret = 0;
exit:
    return ret;
}

int ecall_dispatcher::process_encryption_header(encryption_header_t* header)
{
    int ret = 1;

    if (header == nullptr)
    {
        TRACE_ENCLAVE("process_encryption_header() failed with a null argument"
                      " for encryption_header_t*");
        goto exit;
    }

    if (m_encrypt)
    {
        // allocate host memory for the header and it will be returned back to
        // the host
        m_header =
            (encryption_header_t*)oe_host_malloc(sizeof(encryption_header_t));
        if (m_header == nullptr)
        {
            TRACE_ENCLAVE("oe_host_malloc failed");
            ret = 1;
            goto exit;
        }

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

    ret = 0;
exit:
    return ret;
}
