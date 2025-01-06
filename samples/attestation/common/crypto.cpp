// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "crypto.h"
#include <openenclave/enclave.h>
#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdlib.h>
#include <string.h>

Crypto::Crypto()
{
    m_initialized = init_openssl3();
}

Crypto::~Crypto()
{
    cleanup_openssl3();
}

/**
 * init_openssl3 initializes the crypto module.
 * openssl 3 initialization. Please refer to openssl documentation for detailed
 * information about the functions used.
 */
bool Crypto::init_openssl3(void)
{
    bool ret = false;
    BIO* mem = nullptr;
    size_t numbytes = 0;
    EVP_PKEY_CTX* ctx = nullptr;
    char* bio_ptr = nullptr;

    if (!(ctx = EVP_PKEY_CTX_new_from_name(NULL, "RSA", NULL)))
    {
        TRACE_ENCLAVE("EVP_PKEY_CTX_new_from_name failed!\n");
        goto exit;
    }
    if (!EVP_PKEY_keygen_init(ctx))
    {
        TRACE_ENCLAVE("EVP_PKEY_keygen_init failed!\n");
        goto exit;
    }
    // default key size 2048 bits, default exponent 65537
    if (!EVP_PKEY_generate(ctx, &rsa_pkey))
    {
        TRACE_ENCLAVE("EVP_PKEY_generate failed!\n");
        goto exit;
    }
    mem = BIO_new(BIO_s_mem());
    if (mem == NULL)
    {
        TRACE_ENCLAVE("BIO_new failed!\n");
        goto exit;
    }
    ret = PEM_write_bio_PUBKEY(mem, rsa_pkey);
    if (ret == 0)
    {
        TRACE_ENCLAVE("PEM_write_bio_PUBKEY failed!\n");
        goto exit;
    }
    numbytes = (size_t)BIO_get_mem_data(mem, &bio_ptr);
    if (numbytes == 0)
    {
        TRACE_ENCLAVE("BIO_get_mem_data failed!\n");
        goto exit;
    }
    memcpy(&m_public_key[0], bio_ptr, numbytes);
    ret = true;
    TRACE_ENCLAVE("openssl 3 initialized.");
exit:
    if (mem)
        BIO_free(mem);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    return ret;
}

/**
 * mbedtls cleanup during shutdown.
 */
void Crypto::cleanup_openssl3(void)
{
    if (rsa_pkey)
        EVP_PKEY_free(rsa_pkey);
    TRACE_ENCLAVE("openssl 3 cleaned up.");
}

/**
 * Get the public key for this enclave.
 */
void Crypto::retrieve_public_key(uint8_t pem_public_key[512])
{
    memcpy(pem_public_key, m_public_key, sizeof(m_public_key));
}

// Compute the sha256 hash of given data.
bool Crypto::Sha256(const uint8_t* data, size_t data_size, uint8_t sha256[32])
{
    int ret = false;
    EVP_MD_CTX* ctx = nullptr;

    if (!(ctx = EVP_MD_CTX_new()))
    {
        TRACE_ENCLAVE("EVP_MD_CTX_new failed!");
        goto exit;
    }

    if (!EVP_DigestInit_ex(ctx, EVP_sha256(), NULL))
    {
        TRACE_ENCLAVE("EVP_DigestInit_ex failed!");
        goto exit;
    }

    if (!EVP_DigestUpdate(ctx, data, data_size))
    {
        TRACE_ENCLAVE("EVP_DigestUpdate failed!");
        goto exit;
    }

    if (!EVP_DigestFinal_ex(ctx, sha256, NULL))
    {
        TRACE_ENCLAVE("EVP_DigestFinal_ex failed!");
        goto exit;
    }

    ret = true;
exit:
    if (ctx)
        EVP_MD_CTX_free(ctx);
    return ret;
}

/**
 * Encrypt encrypts the given data using the given public key.
 * Used to encrypt data using the public key of another enclave.
 */
bool Crypto::Encrypt(
    const uint8_t* pem_public_key,
    const uint8_t* data,
    size_t data_size,
    uint8_t* encrypted_data,
    size_t* encrypted_data_size)
{
    BIO* mem = nullptr;
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = nullptr;
    bool result = false;

    if (!(mem = BIO_new(BIO_s_mem())))
    {
        TRACE_ENCLAVE("BIO_new failed!");
        goto exit;
    }
    if (!BIO_write(mem, pem_public_key, 512))
    {
        TRACE_ENCLAVE("BIO_write failed!");
        goto exit;
    }
    if (!(pkey = PEM_read_bio_PUBKEY(mem, NULL, NULL, NULL)))
    {
        TRACE_ENCLAVE("PEM_read_bio_PUBKEY failed!");
        goto exit;
    }
    if (!(ctx = EVP_PKEY_CTX_new(pkey, NULL)))
    {
        TRACE_ENCLAVE("EVP_PKEY_CTX_new failed!");
        goto exit;
    }
    if (!EVP_PKEY_encrypt_init(ctx))
    {
        TRACE_ENCLAVE("EVP_PKEY_encrypt_init failed!");
        goto exit;
    }
    if (!EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING))
    {
        TRACE_ENCLAVE("EVP_PKEY_CTX_set_rsa_padding failed!");
        goto exit;
    }
    if (!EVP_PKEY_encrypt(
            ctx, NULL, encrypted_data_size, (unsigned char*)data, data_size))
    {
        TRACE_ENCLAVE("EVP_PKEY_encrypt failed!");
        goto exit;
    }
    if (!(encrypted_data = (uint8_t*)OPENSSL_malloc(*encrypted_data_size)))
    {
        TRACE_ENCLAVE("OPENSSL_malloc failed!");
        goto exit;
    }
    if (!EVP_PKEY_encrypt(
            ctx,
            encrypted_data,
            encrypted_data_size,
            (unsigned char*)data,
            data_size))
    {
        TRACE_ENCLAVE("EVP_PKEY_encrypt failed!");
        goto exit;
    }
    result = true;
exit:
    if (mem)
        BIO_free(mem);
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    if (pkey)
        EVP_PKEY_free(pkey);
    return result;
}
/**
 * decrypt the given data using current enclave's private key.
 * Used to receive encrypted data from another enclave.
 */
bool Crypto::Decrypt(
    const uint8_t* encrypted_data,
    size_t encrypted_data_size,
    uint8_t* data,
    size_t* data_size)
{
    bool ret = false;
    EVP_PKEY_CTX* ctx = nullptr;

    if (!(ctx = EVP_PKEY_CTX_new(rsa_pkey, NULL)))
    {
        TRACE_ENCLAVE("EVP_PKEY_CTX_new failed!");
        goto exit;
    }
    if (!EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_OAEP_PADDING))
    {
        TRACE_ENCLAVE("EVP_PKEY_CTX_set_rsa_padding failed!");
        goto exit;
    }
    if (!EVP_PKEY_decrypt(
            ctx,
            NULL,
            data_size,
            (unsigned char*)encrypted_data,
            encrypted_data_size))
    {
        TRACE_ENCLAVE("EVP_PKEY_decrypt failed!");
        goto exit;
    }
    if (!(data = (uint8_t*)OPENSSL_malloc(*data_size)))
    {
        TRACE_ENCLAVE("OPENSSL_malloc failed!");
        goto exit;
    }
    if (!EVP_PKEY_decrypt(
            ctx,
            data,
            data_size,
            (unsigned char*)encrypted_data,
            encrypted_data_size))
    {
        TRACE_ENCLAVE("EVP_PKEY_decrypt failed!");
        goto exit;
    }
    ret = true;

exit:
    if (ctx)
        EVP_PKEY_CTX_free(ctx);
    return ret;
}
