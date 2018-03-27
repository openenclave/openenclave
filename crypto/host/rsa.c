// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/bits/sha.h>
#include <openenclave/bits/trace.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>
#include "../util.h"
#include "init.h"

/*
**==============================================================================
**
** Local defintions:
**
**==============================================================================
*/

#define OE_RSA_KEY_MAGIC 0x2a11ed055e91b281

typedef struct _OE_RSA_KEY_IMPL
{
    uint64_t magic;
    RSA* rsa;
} OE_RSA_KEY_IMPL;

OE_STATIC_ASSERT(sizeof(OE_RSA_KEY_IMPL) <= sizeof(OE_RSA_KEY));

OE_INLINE void _ClearImpl(OE_RSA_KEY_IMPL* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->rsa = NULL;
    }
}

OE_INLINE bool _ValidImpl(const OE_RSA_KEY_IMPL* impl)
{
    return impl && impl->magic == OE_RSA_KEY_MAGIC && impl->rsa ? true : false;
}

static int _MapHashType(OE_HashType md)
{
    switch (md)
    {
        case OE_HASH_TYPE_SHA256:
            return NID_sha256;
        case OE_HASH_TYPE_SHA512:
            return NID_sha512;
    }

    /* Unreachable */
    return 0;
}

/*
**==============================================================================
**
** Public defintions:
**
**==============================================================================
*/

OE_Result OE_RSAReadPrivateKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSA_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;
    BIO* bio = NULL;
    RSA* rsa = NULL;

    /* Initialize the key output parameter */
    _ClearImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for loading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_THROW(OE_FAILURE);

    /* Read the RSA structure from the PEM data */
    if (!(rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL)))
        OE_THROW(OE_FAILURE);

    /* Set the output key parameter */
    impl->magic = OE_RSA_KEY_MAGIC;
    impl->rsa = rsa;
    rsa = NULL;

    OE_THROW(OE_OK);

OE_CATCH:

    if (rsa)
        RSA_free(rsa);

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_RSAReadPublicKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSA_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;
    BIO* bio = NULL;
    RSA* rsa = NULL;
    EVP_PKEY* pkey = NULL;

    /* Initialize the key output parameter */
    _ClearImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for loading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_THROW(OE_FAILURE);

    /* Read the RSA structure from the PEM data */
    if (!(pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)))
        OE_THROW(OE_FAILURE);

    /* Get RSA key from public key without increasing reference count */
    if (!(rsa = EVP_PKEY_get1_RSA(pkey)))
        OE_THROW(OE_FAILURE);

    /* Increase reference count of RSA key */
    RSA_up_ref(rsa);

    /* Set the output key parameter */
    impl->magic = OE_RSA_KEY_MAGIC;
    impl->rsa = rsa;
    rsa = NULL;

    OE_THROW(OE_OK);

OE_CATCH:

    if (rsa)
        RSA_free(rsa);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_RSAWritePrivateKeyPEM(
    const OE_RSA_KEY* key,
    uint8_t* data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_RSA_KEY_IMPL* impl = (const OE_RSA_KEY_IMPL*)key;
    BIO* bio = NULL;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_ValidImpl(impl) || !size)
        OE_THROW(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Create memory BIO to write to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_THROW(OE_FAILURE);

    /* Write key to the BIO */
    if (!PEM_write_bio_RSAPrivateKey(bio, impl->rsa, NULL, NULL, 0, NULL, NULL))
    {
        OE_THROW(OE_FAILURE);
    }

    /* Write a null terminator onto the BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        OE_THROW(OE_FAILURE);

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_THROW(OE_FAILURE);

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            OE_THROW(OE_BUFFER_TOO_SMALL);
        }

        /* Copy buffer onto caller's memory */
        memcpy(data, mem->data, mem->length);
        *size = mem->length;
    }

    OE_THROW(OE_OK);

OE_CATCH:

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_RSAWritePublicKeyPEM(
    const OE_RSA_KEY* key,
    uint8_t* data,
    size_t* size)
{
    const OE_RSA_KEY_IMPL* impl = (const OE_RSA_KEY_IMPL*)key;
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_ValidImpl(impl) || !size)
        OE_THROW(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_THROW(OE_FAILURE);

    /* Create PKEY wrapper structure */
    if (!(pkey = EVP_PKEY_new()))
        OE_THROW(OE_FAILURE);

    /* Assign key into PKEY wrapper structure */
    {
        if (!(EVP_PKEY_assign_RSA(pkey, impl->rsa)))
            OE_THROW(OE_FAILURE);

        RSA_up_ref(impl->rsa);
    }

    /* Write key to BIO */
    if (!PEM_write_bio_PUBKEY(bio, pkey))
        OE_THROW(OE_FAILURE);

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        OE_THROW(OE_FAILURE);

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_THROW(OE_FAILURE);

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            OE_THROW(OE_BUFFER_TOO_SMALL);
        }

        /* Copy buffer onto caller's memory */
        memcpy(data, mem->data, mem->length);
        *size = mem->length;
    }

    OE_THROW(OE_OK);

OE_CATCH:

    if (bio)
        BIO_free(bio);

    if (pkey)
        EVP_PKEY_free(pkey);

    return result;
}

OE_Result OE_RSAFree(OE_RSA_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;

    /* Check the parameter */
    if (!_ValidImpl(impl))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Release the RSA object */
    RSA_free(impl->rsa);

    /* Clear the fields in the implementation */
    _ClearImpl(impl);

    OE_THROW(OE_OK);

OE_CATCH:
    return result;
}

OE_Result OE_RSASign(
    const OE_RSA_KEY* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)privateKey;
    int type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_ValidImpl(impl) || !hashData || !hashSize || !signatureSize)
        OE_THROW(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Determine the size of the signature; fail if buffer is too small */
    {
        size_t size = RSA_size(impl->rsa);

        if (size > *signatureSize)
        {
            *signatureSize = size;
            OE_THROW(OE_BUFFER_TOO_SMALL);
        }

        *signatureSize = size;
    }

    /* Verify that the data is signed by the given RSA private key */
    unsigned int siglen;
    if (!RSA_sign(type, hashData, hashSize, signature, &siglen, impl->rsa))
        OE_THROW(OE_FAILURE);

    /* This should never happen */
    if (siglen != *signatureSize)
        OE_THROW(OE_UNEXPECTED);

    OE_THROW(OE_OK);

OE_CATCH:

    return result;
}

OE_Result OE_RSAVerify(
    const OE_RSA_KEY* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)publicKey;
    int type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_ValidImpl(impl) || !hashSize || !hashData || !signature ||
        signatureSize == 0)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Verify that the data is signed by the given RSA private key */
    if (!RSA_verify(
            type, hashData, hashSize, signature, signatureSize, impl->rsa))
    {
        OE_THROW(OE_FAILURE);
    }

    OE_THROW(OE_OK);

OE_CATCH:

    return result;
}

OE_Result OE_RSAGenerate(
    uint64_t bits,
    uint64_t exponent,
    OE_RSA_KEY* privateKey,
    OE_RSA_KEY* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* privateImpl = (OE_RSA_KEY_IMPL*)privateKey;
    OE_RSA_KEY_IMPL* publicImpl = (OE_RSA_KEY_IMPL*)publicKey;
    RSA* rsa = NULL;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    _ClearImpl(privateImpl);
    _ClearImpl(publicImpl);

    /* Check parameters */
    if (!privateImpl || !publicImpl)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Check range of bits parameter */
    if (bits > INT_MAX)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Check range of exponent parameter */
    if (exponent > ULONG_MAX)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Generate an RSA key pair */
    if (!(rsa = RSA_generate_key(bits, exponent, 0, 0)))
        OE_THROW(OE_FAILURE);

    /* Copy the private key from the key-pair */
    {
        if (!(privateImpl->rsa = RSAPrivateKey_dup(rsa)))
            OE_THROW(OE_FAILURE);

        privateImpl->magic = OE_RSA_KEY_MAGIC;
    }

    /* Copy the public key from the key-pair */
    {
        if (!(publicImpl->rsa = RSAPublicKey_dup(rsa)))
            OE_THROW(OE_FAILURE);

        publicImpl->magic = OE_RSA_KEY_MAGIC;
    }

    OE_THROW(OE_OK);

OE_CATCH:

    if (rsa)
        RSA_free(rsa);

    if (bio)
        BIO_free(bio);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (result != OE_OK)
    {
        if (_ValidImpl(privateImpl))
            OE_RSAFree(privateKey);

        if (_ValidImpl(publicImpl))
            OE_RSAFree(publicKey);
    }

    return result;
}
