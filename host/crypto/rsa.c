// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <limits.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/bits/sha.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <stdio.h>
#include <string.h>
#include "init.h"
#include "rsa.h"

/*
**==============================================================================
**
** Local defintions (local to this source file)
**
**==============================================================================
*/

/* Randomly generated magic number */
#define OE_RSA_PRIVATE_KEY_MAGIC 0x7bf635929a714b2c

typedef struct _OE_RSAPrivateKeyImpl
{
    uint64_t magic;
    RSA* rsa;
} OE_RSAPrivateKeyImpl;

OE_STATIC_ASSERT(sizeof(OE_RSAPrivateKeyImpl) <= sizeof(OE_RSAPrivateKey));

OE_INLINE void _ClearPrivateKeyImpl(OE_RSAPrivateKeyImpl* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->rsa = NULL;
    }
}

OE_INLINE bool _ValidPrivateKeyImpl(const OE_RSAPrivateKeyImpl* impl)
{
    return impl && impl->magic == OE_RSA_PRIVATE_KEY_MAGIC && impl->rsa;
}

/* Randomly generated magic number */
#define OE_RSA_PUBLIC_KEY_MAGIC 0x8f8f72170025426d

typedef struct _OE_RSAPublicKeyImpl
{
    uint64_t magic;
    RSA* rsa;
} OE_RSAPublicKeyImpl;

OE_STATIC_ASSERT(sizeof(OE_RSAPublicKeyImpl) <= sizeof(OE_RSAPublicKey));

OE_INLINE void _ClearPublicKeyImpl(OE_RSAPublicKeyImpl* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->rsa = NULL;
    }
}

OE_INLINE bool _ValidPublicKeyImpl(const OE_RSAPublicKeyImpl* impl)
{
    return impl && impl->magic == OE_RSA_PUBLIC_KEY_MAGIC && impl->rsa;
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

static void _RSAInitPrivateKey(OE_RSAPrivateKey* privateKey, RSA* rsa)
{
    OE_RSAPrivateKeyImpl* impl = (OE_RSAPrivateKeyImpl*)privateKey;
    impl->magic = OE_RSA_PRIVATE_KEY_MAGIC;
    impl->rsa = rsa;
}

/*
**==============================================================================
**
** Shared definitions (shared within this directory)
**
**==============================================================================
*/

void OE_RSAInitPublicKey(OE_RSAPublicKey* publicKey, RSA* rsa)
{
    OE_RSAPublicKeyImpl* impl = (OE_RSAPublicKeyImpl*)publicKey;
    impl->magic = OE_RSA_PUBLIC_KEY_MAGIC;
    impl->rsa = rsa;
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
    OE_RSAPrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSAPrivateKeyImpl* impl = (OE_RSAPrivateKeyImpl*)key;
    BIO* bio = NULL;
    RSA* rsa = NULL;

    /* Initialize the key output parameter */
    _ClearPrivateKeyImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for loading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_RAISE(OE_FAILURE);

    /* Read the RSA structure from the PEM data */
    if (!(rsa = PEM_read_bio_RSAPrivateKey(bio, &rsa, NULL, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Set the output key parameter */
    _RSAInitPrivateKey(key, rsa);
    rsa = NULL;

    result = OE_OK;

done:

    if (rsa)
        RSA_free(rsa);

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_RSAReadPublicKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPublicKey* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSAPublicKeyImpl* impl = (OE_RSAPublicKeyImpl*)key;
    BIO* bio = NULL;
    RSA* rsa = NULL;
    EVP_PKEY* pkey = NULL;

    /* Initialize the key output parameter */
    _ClearPublicKeyImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for loading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_RAISE(OE_FAILURE);

    /* Read the RSA structure from the PEM data */
    if (!(pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Get RSA key from public key without increasing reference count */
    if (!(rsa = EVP_PKEY_get1_RSA(pkey)))
        OE_RAISE(OE_FAILURE);

    /* Increase reference count of RSA key */
    RSA_up_ref(rsa);

    /* Set the output key parameter */
    OE_RSAInitPublicKey(key, rsa);
    rsa = NULL;

    result = OE_OK;

done:

    if (rsa)
        RSA_free(rsa);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_RSAWritePrivateKeyPEM(
    const OE_RSAPrivateKey* key,
    uint8_t* data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_RSAPrivateKeyImpl* impl = (const OE_RSAPrivateKeyImpl*)key;
    BIO* bio = NULL;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_ValidPrivateKeyImpl(impl) || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create memory BIO to write to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_FAILURE);

    /* Write key to the BIO */
    if (!PEM_write_bio_RSAPrivateKey(bio, impl->rsa, NULL, NULL, 0, NULL, NULL))
    {
        OE_RAISE(OE_FAILURE);
    }

    /* Write a null terminator onto the BIO */
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

OE_Result OE_RSAWritePublicKeyPEM(
    const OE_RSAPublicKey* key,
    uint8_t* data,
    size_t* size)
{
    const OE_RSAPublicKeyImpl* impl = (const OE_RSAPublicKeyImpl*)key;
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_ValidPublicKeyImpl(impl) || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_FAILURE);

    /* Create PKEY wrapper structure */
    if (!(pkey = EVP_PKEY_new()))
        OE_RAISE(OE_FAILURE);

    /* Assign key into PKEY wrapper structure */
    {
        if (!(EVP_PKEY_assign_RSA(pkey, impl->rsa)))
            OE_RAISE(OE_FAILURE);

        RSA_up_ref(impl->rsa);
    }

    /* Write key to BIO */
    if (!PEM_write_bio_PUBKEY(bio, pkey))
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

    if (pkey)
        EVP_PKEY_free(pkey);

    return result;
}

OE_Result OE_RSAFreePrivateKey(OE_RSAPrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        OE_RSAPrivateKeyImpl* impl = (OE_RSAPrivateKeyImpl*)key;

        /* Check the parameter */
        if (!_ValidPrivateKeyImpl(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the RSA object */
        RSA_free(impl->rsa);

        /* Clear the fields in the implementation */
        _ClearPrivateKeyImpl(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_RSAFreePublicKey(OE_RSAPublicKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        OE_RSAPublicKeyImpl* impl = (OE_RSAPublicKeyImpl*)key;

        /* Check the parameter */
        if (!_ValidPublicKeyImpl(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the RSA object */
        RSA_free(impl->rsa);

        /* Clear the fields in the implementation */
        _ClearPublicKeyImpl(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_RSASign(
    const OE_RSAPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_RSAPrivateKeyImpl* impl = (OE_RSAPrivateKeyImpl*)privateKey;
    int type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_ValidPrivateKeyImpl(impl) || !hashData || !hashSize || !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Determine the size of the signature; fail if buffer is too small */
    {
        size_t size = RSA_size(impl->rsa);

        if (size > *signatureSize)
        {
            *signatureSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        *signatureSize = size;
    }

    /* Verify that the data is signed by the given RSA private key */
    unsigned int siglen;
    if (!RSA_sign(type, hashData, hashSize, signature, &siglen, impl->rsa))
        OE_RAISE(OE_FAILURE);

    /* This should never happen */
    if (siglen != *signatureSize)
        OE_RAISE(OE_UNEXPECTED);

    result = OE_OK;

done:

    return result;
}

OE_Result OE_RSAVerify(
    const OE_RSAPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_RSAPublicKeyImpl* impl = (OE_RSAPublicKeyImpl*)publicKey;
    int type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_ValidPublicKeyImpl(impl) || !hashSize || !hashData || !signature ||
        signatureSize == 0)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Verify that the data is signed by the given RSA private key */
    if (!RSA_verify(
            type, hashData, hashSize, signature, signatureSize, impl->rsa))
    {
        OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:

    return result;
}

OE_Result OE_RSAGenerate(
    uint64_t bits,
    uint64_t exponent,
    OE_RSAPrivateKey* privateKey,
    OE_RSAPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSAPrivateKeyImpl* privateImpl = (OE_RSAPrivateKeyImpl*)privateKey;
    OE_RSAPublicKeyImpl* publicImpl = (OE_RSAPublicKeyImpl*)publicKey;
    RSA* rsa = NULL;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    _ClearPrivateKeyImpl(privateImpl);
    _ClearPublicKeyImpl(publicImpl);

    /* Check parameters */
    if (!privateImpl || !publicImpl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check range of bits parameter */
    if (bits > INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check range of exponent parameter */
    if (exponent > ULONG_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Generate an RSA key pair */
    if (!(rsa = RSA_generate_key(bits, exponent, 0, 0)))
        OE_RAISE(OE_FAILURE);

    /* Copy the private key from the key-pair */
    {
        RSA* privateRSA;

        if (!(privateRSA = RSAPrivateKey_dup(rsa)))
            OE_RAISE(OE_FAILURE);

        _RSAInitPrivateKey(privateKey, privateRSA);
    }

    /* Copy the public key from the key-pair */
    {
        RSA* publicRSA;

        if (!(publicRSA = RSAPublicKey_dup(rsa)))
            OE_RAISE(OE_FAILURE);

        OE_RSAInitPublicKey(publicKey, publicRSA);
    }

    result = OE_OK;

done:

    if (rsa)
        RSA_free(rsa);

    if (bio)
        BIO_free(bio);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (result != OE_OK)
    {
        OE_RSAFreePrivateKey(privateKey);
        OE_RSAFreePublicKey(publicKey);
    }

    return result;
}

OE_Result OE_RSAGetPublicKeyInfo(
    const OE_RSAPublicKey* publicKey,
    OE_RSAPublicKeyInfo* info)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSAPublicKeyImpl* impl = (OE_RSAPublicKeyImpl*)publicKey;

    /* Clear the information in case of failure */
    if (info)
        memset(info, 0, sizeof(OE_RSAPublicKeyInfo));

    /* Reject invalid parameters */
    if (!_ValidPublicKeyImpl(impl) || !info)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the number of bytes in the modulus */
    {
        int n = RSA_size(impl->rsa);

        if (n <= 0)
            OE_RAISE(OE_FAILURE);

        info->numModulusBytes = (uint32_t)n;
    }

    /* Get the number of modulus bits */
    {
        int n = BN_num_bits(impl->rsa->n);

        if (n <= 0)
            OE_RAISE(OE_FAILURE);

        info->numModulusBits = (uint32_t)n;
    }

    /* Get the number of bytes in the public exponent */
    {
        int n = BN_num_bytes(impl->rsa->e);

        if (n <= 0)
            OE_RAISE(OE_FAILURE);

        info->numExponentBytes = (uint32_t)n;
    }

    /* Get the number of exponent public bits */
    {
        int n = BN_num_bits(impl->rsa->e);

        if (n <= 0)
            OE_RAISE(OE_FAILURE);

        info->numExponentBits = (uint32_t)n;
    }

    /* Note that for public keys, rsa->d is null */

    result = OE_OK;

done:

    return result;
}
