// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/ec.h>
#include <openenclave/bits/sha.h>
#include <openenclave/types.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
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

#define OE_EC_KEY_MAGIC 0x278c216447aa1f84

typedef struct _OE_EC_KEY_IMPL
{
    uint64_t magic;
    EVP_PKEY* pkey;
} OE_EC_KEY_IMPL;

OE_STATIC_ASSERT(sizeof(OE_EC_KEY_IMPL) <= sizeof(OE_EC_KEY));

OE_INLINE void _ClearImpl(OE_EC_KEY_IMPL* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->pkey = NULL;
    }
}

OE_INLINE bool _ValidImpl(const OE_EC_KEY_IMPL* impl)
{
    return impl && impl->magic == OE_EC_KEY_MAGIC && impl->pkey ? true : false;
}

/* Curve names, indexed by OE_ECType */
static const char* _curveNames[] = {
    "secp521r1" /* OE_EC_TYPE_SECP521R1 */
};

/* Convert ECType to curve name */
static const char* _ECTypeToString(OE_Type type)
{
    size_t index = (size_t)type;

    if (index >= OE_COUNTOF(_curveNames))
        return NULL;

    return _curveNames[index];
}

/*
**==============================================================================
**
** Public functions:
**
**==============================================================================
*/

OE_Result OE_ECReadPrivateKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_EC_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_EC_KEY_IMPL* impl = (OE_EC_KEY_IMPL*)key;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    /* Initialize the key output parameter */
    _ClearImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        goto done;

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)))
        goto done;

    /* Initialize the key */
    impl->magic = OE_EC_KEY_MAGIC;
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

OE_Result OE_ECReadPublicKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_EC_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;
    OE_EC_KEY_IMPL* impl = (OE_EC_KEY_IMPL*)key;

    /* Zero-initialize the key */
    _ClearImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* The position of the null terminator must be the last byte */
    if (OE_CheckForNullTerminator(pemData, pemSize) != OE_OK)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        goto done;

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)))
        goto done;

    /* Initialize the key */
    impl->magic = OE_EC_KEY_MAGIC;
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

OE_Result OE_ECWritePrivateKeyPEM(
    const OE_EC_KEY* key,
    uint8_t* data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_EC_KEY_IMPL* impl = (const OE_EC_KEY_IMPL*)key;
    BIO* bio = NULL;
    EC_KEY* ec;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_ValidImpl(impl) || !size)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Get EC key from public key without increasing reference count */
    if (!(ec = EVP_PKEY_get1_EC_KEY(impl->pkey)))
        goto done;

    /* Write key to BIO */
    if (!PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, 0, NULL))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
        {
            result = OE_FAILURE;
            goto done;
        }

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            result = OE_BUFFER_TOO_SMALL;
            goto done;
        }

        /* Copy buffer onto caller's memory */
        memcpy(data, mem->data, mem->length);
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_ECWritePublicKeyPEM(
    const OE_EC_KEY* key,
    uint8_t* data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    const OE_EC_KEY_IMPL* impl = (const OE_EC_KEY_IMPL*)key;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_ValidImpl(impl) || !size)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Write key to BIO */
    if (!PEM_write_bio_PUBKEY(bio, impl->pkey))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Write a NULL terminator onto BIO */
    if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Copy the BIO onto caller's memory */
    {
        BUF_MEM* mem;

        if (!BIO_get_mem_ptr(bio, &mem))
        {
            result = OE_FAILURE;
            goto done;
        }

        /* If buffer is too small */
        if (*size < mem->length)
        {
            *size = mem->length;
            result = OE_BUFFER_TOO_SMALL;
            goto done;
        }

        /* Copy buffer onto caller's memory */
        memcpy(data, mem->data, mem->length);
        *size = mem->length;
    }

    result = OE_OK;

done:

    if (bio)
        BIO_free(bio);

    return result;
}

OE_Result OE_ECFree(OE_EC_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_EC_KEY_IMPL* impl = (OE_EC_KEY_IMPL*)key;

    /* Check parameter */
    if (!_ValidImpl(impl))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Release the key */
    EVP_PKEY_free(impl->pkey);

    /* Clear the fields of the implementation */
    _ClearImpl(impl);

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ECSign(
    const OE_EC_KEY* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_EC_KEY_IMPL* impl = (const OE_EC_KEY_IMPL*)privateKey;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!_ValidImpl(impl) || !hashData || !hashSize || !signatureSize)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Check that hash buffer is big enough (hashType is size of that hash) */
    if (hashType > hashSize)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(impl->pkey, NULL)))
        goto done;

    /* Initialize the signing context */
    if (EVP_PKEY_sign_init(ctx) <= 0)
        goto done;

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        goto done;

    /* Determine the size of the signature; fail if buffer is too small */
    {
        size_t size;

        if (EVP_PKEY_sign(ctx, NULL, &size, hashData, hashSize) <= 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        if (size > *signatureSize)
        {
            *signatureSize = size;
            result = OE_BUFFER_TOO_SMALL;
            goto done;
        }

        *signatureSize = size;
    }

    /* Compute the signature */
    if (EVP_PKEY_sign(ctx, signature, signatureSize, hashData, hashSize) <= 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}

OE_Result OE_ECVerify(
    const OE_EC_KEY* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_EC_KEY_IMPL* impl = (const OE_EC_KEY_IMPL*)publicKey;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!_ValidImpl(impl) || !hashData || !hashSize || !signature ||
        !signatureSize)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Check that hash buffer is big enough (hashType is size of that hash) */
    if (hashType > hashSize)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create signing context */
    if (!(ctx = EVP_PKEY_CTX_new(impl->pkey, NULL)))
        goto done;

    /* Initialize the signing context */
    if (EVP_PKEY_verify_init(ctx) <= 0)
        goto done;

    /* Set the MD type for the signing operation */
    if (EVP_PKEY_CTX_set_signature_md(ctx, EVP_sha256()) <= 0)
        goto done;

    /* Compute the signature */
    if (EVP_PKEY_verify(ctx, signature, signatureSize, hashData, hashSize) <= 0)
    {
        goto done;
    }

    result = OE_OK;

done:

    if (ctx)
        EVP_PKEY_CTX_free(ctx);

    return result;
}

OE_Result OE_ECGenerate(
    OE_ECType type,
    OE_EC_KEY* privateKey,
    OE_EC_KEY* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_EC_KEY_IMPL* privateImpl = (OE_EC_KEY_IMPL*)privateKey;
    OE_EC_KEY_IMPL* publicImpl = (OE_EC_KEY_IMPL*)publicKey;
    int nid;
    EC_KEY* key = NULL;
    EVP_PKEY* pkey = NULL;
    BIO* bio = NULL;
    const char nullTerminator = '\0';
    const char* curveName;

    _ClearImpl(privateImpl);
    _ClearImpl(publicImpl);

    /* Check parameters */
    if (!privateKey || !publicKey)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    if (!(curveName = _ECTypeToString(type)))
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Resolve the NID for this curve name */
    if ((nid = OBJ_txt2nid(curveName)) == NID_undef)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Create the key */
    if (!(key = EC_KEY_new_by_curve_name(nid)))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Set the EC named-curve flag */
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    /* Generate the public/private key pair */
    if (!EC_KEY_generate_key(key))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Create the private key structure */
    if (!(pkey = EVP_PKEY_new()))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Initialize the private key from the generated key pair */
    if (!EVP_PKEY_assign_EC_KEY(pkey, key))
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Key will be released when pkey is released */
    key = NULL;

    /* Create private key object */
    {
        BUF_MEM* mem;

        if (!(bio = BIO_new(BIO_s_mem())))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!BIO_get_mem_ptr(bio, &mem))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (OE_ECReadPrivateKeyPEM(
                (uint8_t*)mem->data, mem->length, privateKey) != OE_OK)
        {
            result = OE_FAILURE;
            goto done;
        }

        BIO_free(bio);
        bio = NULL;
    }

    /* Create public key object */
    {
        BUF_MEM* mem;

        if (!(bio = BIO_new(BIO_s_mem())))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (!PEM_write_bio_PUBKEY(bio, pkey))
        {
            result = OE_FAILURE;
            goto done;
        }

        if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
        {
            result = OE_FAILURE;
            goto done;
        }

        BIO_get_mem_ptr(bio, &mem);

        if (OE_ECReadPublicKeyPEM(
                (uint8_t*)mem->data, mem->length, publicKey) != OE_OK)
        {
            result = OE_FAILURE;
            goto done;
        }

        BIO_free(bio);
        bio = NULL;
    }

    result = OE_OK;

done:

    if (key)
        EC_KEY_free(key);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    if (result != OE_OK)
    {
        if (_ValidImpl(privateImpl))
            OE_ECFree(privateKey);

        if (_ValidImpl(publicImpl))
            OE_ECFree(publicKey);
    }

    return result;
}
