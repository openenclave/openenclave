// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "key.h"
#include <openenclave/bits/raise.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include "init.h"

bool oe_private_key_is_valid(const oe_private_key_t* impl, uint64_t magic)
{
    return impl && impl->magic == magic && impl->pkey;
}

bool oe_public_key_is_valid(const oe_public_key_t* impl, uint64_t magic)
{
    return impl && impl->magic == magic && impl->pkey;
}

void oe_public_key_init(oe_public_key_t* publicKey, EVP_PKEY* pkey, uint64_t magic)
{
    oe_public_key_t* impl = (oe_public_key_t*)publicKey;
    impl->magic = magic;
    impl->pkey = pkey;
}

void oe_private_key_init(
    oe_private_key_t* privateKey,
    EVP_PKEY* pkey,
    uint64_t magic)
{
    oe_private_key_t* impl = (oe_private_key_t*)privateKey;
    impl->magic = magic;
    impl->pkey = pkey;
}

oe_result_t oe_private_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_private_key_t* key,
    int keyType,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* impl = (oe_private_key_t*)key;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    /* Initialize the key output parameter */
    if (impl)
        memset(impl, 0, sizeof(*impl));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_open_ssl();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_RAISE(OE_FAILURE);

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Verify that it is the right key type */
    if (pkey->type != keyType)
        OE_RAISE(OE_FAILURE);

    /* Initialize the key */
    impl->magic = magic;
    impl->pkey = pkey;
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_public_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_public_key_t* key,
    int keyType,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;
    oe_public_key_t* impl = (oe_public_key_t*)key;

    /* Zero-initialize the key */
    if (impl)
        memset(impl, 0, sizeof(*impl));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_open_ssl();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_RAISE(OE_FAILURE);

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Verify that it is the right key type */
    if (pkey->type != keyType)
        OE_RAISE(OE_FAILURE);

    /* Initialize the key */
    impl->magic = magic;
    impl->pkey = pkey;
    pkey = NULL;

    result = OE_OK;

done:

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_private_key_write_pem(
    const oe_private_key_t* privateKey,
    uint8_t* data,
    size_t* size,
    oe_private_key_write_pem_callback privateKeyWritePEMCallback,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_private_key_t* impl = (const oe_private_key_t*)privateKey;
    BIO* bio = NULL;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!oe_private_key_is_valid(impl, magic) || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_FAILURE);

    /* Write key to BIO */
    OE_CHECK(privateKeyWritePEMCallback(bio, impl->pkey));

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_RAISE(OE_FAILURE);

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /* Copy result to output buffer */
        memcpy(data, mem->data, mem->length);
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_public_key_write_pem(
    const oe_public_key_t* key,
    uint8_t* data,
    size_t* size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    BIO* bio = NULL;
    const oe_public_key_t* impl = (const oe_public_key_t*)key;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!oe_public_key_is_valid(impl, magic) || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_FAILURE);

    /* Write key to BIO */
    if (!PEM_write_bio_PUBKEY(bio, impl->pkey))
        OE_RAISE(OE_FAILURE);

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_RAISE(OE_FAILURE);

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /* Copy result to output buffer */
        memcpy(data, mem->data, mem->length);
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}

oe_result_t oe_private_key_free(oe_private_key_t* key, uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (key)
    {
        oe_private_key_t* impl = (oe_private_key_t*)key;

        /* Check parameter */
        if (!oe_private_key_is_valid(impl, magic))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        EVP_PKEY_free(impl->pkey);

        /* Clear the fields of the implementation */
        if (impl)
            memset(impl, 0, sizeof(*impl));
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_public_key_free(oe_public_key_t* key, uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (key)
    {
        oe_public_key_t* impl = (oe_public_key_t*)key;

        /* Check parameter */
        if (!oe_public_key_is_valid(impl, magic))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        EVP_PKEY_free(impl->pkey);

        /* Clear the fields of the implementation */
        if (impl)
            memset(impl, 0, sizeof(*impl));
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_private_key_sign(
    const oe_private_key_t* privateKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_private_key_t* impl = (const oe_private_key_t*)privateKey;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!oe_private_key_is_valid(impl, magic) || !hashData || !hashSize ||
        !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check that hash buffer is big enough (hashType is size of that hash) */
    if (hashType > hashSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_open_ssl();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(impl->pkey, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Initialize the signing context */
    if (EVP_PKEY_sign_init(ctx) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Determine the size of the signature; fail if buffer is too small */
    {
        size_t size;

        if (EVP_PKEY_sign(ctx, NULL, &size, hashData, hashSize) <= 0)
            OE_RAISE(OE_FAILURE);

        if (size > *signatureSize)
        {
            *signatureSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        *signatureSize = size;
    }

    /* Compute the signature */
    if (EVP_PKEY_sign(ctx, signature, signatureSize, hashData, hashSize) <= 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}

oe_result_t oe_public_key_verify(
    const oe_public_key_t* publicKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)publicKey;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!oe_public_key_is_valid(impl, magic) || !hashData || !hashSize ||
        !signature || !signatureSize)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Check that hash buffer is big enough (hashType is size of that hash) */
    if (hashType > hashSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_open_ssl();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(impl->pkey, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Initialize the signing context */
    if (EVP_PKEY_verify_init(ctx) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Compute the signature */
    if (EVP_PKEY_verify(ctx, signature, signatureSize, hashData, hashSize) <= 0)
        OE_RAISE(OE_VERIFY_FAILED);

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}
