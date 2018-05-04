// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <openenclave/bits/ec.h>
#include <openenclave/bits/pem.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/sha.h>
#include <openenclave/types.h>
#include <openssl/pem.h>
#include <string.h>
#include "init.h"

/*
**==============================================================================
**
** Local defintions:
**
**==============================================================================
*/

/* Randomly generated magic number */
#define OE_EC_PRIVATE_KEY_MAGIC 0x19a751419ae04bbc

typedef struct _ECPrivateKey
{
    uint64_t magic;
    EVP_PKEY* pkey;
} ECPrivateKey;

OE_STATIC_ASSERT(sizeof(ECPrivateKey) <= sizeof(OE_ECPrivateKey));

OE_INLINE void _ECPrivateKeyClear(ECPrivateKey* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->pkey = NULL;
    }
}

OE_INLINE bool _ECPrivateKeyValid(const ECPrivateKey* impl)
{
    return impl && impl->magic == OE_EC_PRIVATE_KEY_MAGIC && impl->pkey;
}

/* Randomly generated magic number */
#define OE_EC_PUBLIC_KEY_MAGIC 0xb1d39580c1f14c02

typedef struct _ECPublicKey
{
    uint64_t magic;
    EVP_PKEY* pkey;
} ECPublicKey;

OE_STATIC_ASSERT(sizeof(ECPublicKey) <= sizeof(OE_ECPublicKey));

OE_INLINE void _ECPublicKeyClear(ECPublicKey* impl)
{
    if (impl)
    {
        impl->magic = 0;
        impl->pkey = NULL;
    }
}

OE_INLINE bool _ECPublicKeyValid(const ECPublicKey* impl)
{
    return impl && impl->magic == OE_EC_PUBLIC_KEY_MAGIC && impl->pkey;
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

/* Get the EC key without incrementing the reference count */
static EC_KEY* _GetECKey(EVP_PKEY* pkey)
{
    EC_KEY* ec;

    if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
        return NULL;

    EC_KEY_free(ec);
    return ec;
}

/*
**==============================================================================
**
** Shared definitions (shared within this directory)
**
**==============================================================================
*/

void OE_ECPublicKeyInit(OE_ECPublicKey* publicKey, EVP_PKEY* pkey)
{
    ECPublicKey* impl = (ECPublicKey*)publicKey;
    impl->magic = OE_EC_PUBLIC_KEY_MAGIC;
    impl->pkey = pkey;
}

/*
**==============================================================================
**
** Public functions:
**
**==============================================================================
*/

OE_Result OE_ECPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;
    ECPrivateKey* impl = (ECPrivateKey*)key;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;

    /* Initialize the key output parameter */
    _ECPrivateKeyClear(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_RAISE(OE_FAILURE);

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PrivateKey(bio, &pkey, NULL, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Verify that it is an EC key */
    if (!_GetECKey(pkey))
        OE_RAISE(OE_FAILURE);

    /* Initialize the key */
    impl->magic = OE_EC_PRIVATE_KEY_MAGIC;
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

OE_Result OE_ECPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPublicKey* key)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    EVP_PKEY* pkey = NULL;
    ECPublicKey* impl = (ECPublicKey*)key;

    /* Zero-initialize the key */
    _ECPublicKeyClear(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create a BIO object for reading the PEM data */
    if (!(bio = BIO_new_mem_buf(pemData, pemSize)))
        OE_RAISE(OE_FAILURE);

    /* Read the key object */
    if (!(pkey = PEM_read_bio_PUBKEY(bio, &pkey, NULL, NULL)))
        OE_RAISE(OE_FAILURE);

    /* Verify that it is an EC key */
    if (!_GetECKey(pkey))
        OE_RAISE(OE_FAILURE);

    /* Initialize the key */
    impl->magic = OE_EC_PUBLIC_KEY_MAGIC;
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

OE_Result OE_ECPrivateKeyWritePEM(
    const OE_ECPrivateKey* key,
    uint8_t* data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    const ECPrivateKey* impl = (const ECPrivateKey*)key;
    BIO* bio = NULL;
    EC_KEY* ec = NULL;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_ECPrivateKeyValid(impl) || !size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!data && *size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create memory BIO object to write key to */
    if (!(bio = BIO_new(BIO_s_mem())))
        OE_RAISE(OE_FAILURE);

    /* Get EC key from public key (increasing reference count) */
    if (!(ec = EVP_PKEY_get1_EC_KEY(impl->pkey)))
        OE_RAISE(OE_FAILURE);

    /* Write key to BIO */
    if (!PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, 0, NULL))
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

    if (ec)
        EC_KEY_free(ec);

    return result;
}

OE_Result OE_ECPublicKeyWritePEM(
    const OE_ECPublicKey* key,
    uint8_t* data,
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    BIO* bio = NULL;
    const ECPublicKey* impl = (const ECPublicKey*)key;
    const char nullTerminator = '\0';

    /* Check parameters */
    if (!_ECPublicKeyValid(impl) || !size)
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

OE_Result OE_ECPrivateKeyFree(OE_ECPrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        ECPrivateKey* impl = (ECPrivateKey*)key;

        /* Check parameter */
        if (!_ECPrivateKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        EVP_PKEY_free(impl->pkey);

        /* Clear the fields of the implementation */
        _ECPrivateKeyClear(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ECPublicKeyFree(OE_ECPublicKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        ECPublicKey* impl = (ECPublicKey*)key;

        /* Check parameter */
        if (!_ECPublicKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        EVP_PKEY_free(impl->pkey);

        /* Clear the fields of the implementation */
        _ECPublicKeyClear(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ECPrivateKeySign(
    const OE_ECPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const ECPrivateKey* impl = (const ECPrivateKey*)privateKey;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!_ECPrivateKeyValid(impl) || !hashData || !hashSize || !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check that hash buffer is big enough (hashType is size of that hash) */
    if (hashType > hashSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

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

OE_Result OE_ECPublicKeyVerify(
    const OE_ECPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const ECPublicKey* impl = (const ECPublicKey*)publicKey;
    EVP_PKEY_CTX* ctx = NULL;

    /* Check for null parameters */
    if (!_ECPublicKeyValid(impl) || !hashData || !hashSize || !signature ||
        !signatureSize)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Check that hash buffer is big enough (hashType is size of that hash) */
    if (hashType > hashSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

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

OE_Result OE_ECGenerateKeyPair(
    OE_ECType type,
    OE_ECPrivateKey* privateKey,
    OE_ECPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    ECPrivateKey* privateImpl = (ECPrivateKey*)privateKey;
    ECPublicKey* publicImpl = (ECPublicKey*)publicKey;
    int nid;
    EC_KEY* key = NULL;
    EVP_PKEY* pkey = NULL;
    BIO* bio = NULL;
    const char nullTerminator = '\0';
    const char* curveName;

    _ECPrivateKeyClear(privateImpl);
    _ECPublicKeyClear(publicImpl);

    /* Check parameters */
    if (!privateKey || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(curveName = _ECTypeToString(type)))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Resolve the NID for this curve name */
    if ((nid = OBJ_txt2nid(curveName)) == NID_undef)
        OE_RAISE(OE_FAILURE);

    /* Create the key */
    if (!(key = EC_KEY_new_by_curve_name(nid)))
        OE_RAISE(OE_FAILURE);

    /* Set the EC named-curve flag */
    EC_KEY_set_asn1_flag(key, OPENSSL_EC_NAMED_CURVE);

    /* Generate the public/private key pair */
    if (!EC_KEY_generate_key(key))
        OE_RAISE(OE_FAILURE);

    /* Create the private key structure */
    if (!(pkey = EVP_PKEY_new()))
        OE_RAISE(OE_FAILURE);

    /* Initialize the private key from the generated key pair */
    if (!EVP_PKEY_assign_EC_KEY(pkey, key))
        OE_RAISE(OE_FAILURE);

    /* Key will be released when pkey is released */
    key = NULL;

    /* Create private key object */
    {
        BUF_MEM* mem;

        if (!(bio = BIO_new(BIO_s_mem())))
            OE_RAISE(OE_FAILURE);

        if (!PEM_write_bio_PrivateKey(bio, pkey, NULL, NULL, 0, 0, NULL))
            OE_RAISE(OE_FAILURE);

        if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
            OE_RAISE(OE_FAILURE);

        if (!BIO_get_mem_ptr(bio, &mem))
            OE_RAISE(OE_FAILURE);

        if (OE_ECPrivateKeyReadPEM(
                (uint8_t*)mem->data, mem->length, privateKey) != OE_OK)
        {
            OE_RAISE(OE_FAILURE);
        }

        BIO_free(bio);
        bio = NULL;
    }

    /* Create public key object */
    {
        BUF_MEM* mem;

        if (!(bio = BIO_new(BIO_s_mem())))
            OE_RAISE(OE_FAILURE);

        if (!PEM_write_bio_PUBKEY(bio, pkey))
            OE_RAISE(OE_FAILURE);

        if (BIO_write(bio, &nullTerminator, sizeof(nullTerminator)) <= 0)
            OE_RAISE(OE_FAILURE);

        BIO_get_mem_ptr(bio, &mem);

        if (OE_ECPublicKeyReadPEM(
                (uint8_t*)mem->data, mem->length, publicKey) != OE_OK)
        {
            OE_RAISE(OE_FAILURE);
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
        OE_ECPrivateKeyFree(privateKey);
        OE_ECPublicKeyFree(publicKey);
    }

    return result;
}

OE_Result OE_ECPublicKeyGetKeyBytes(
    const OE_ECPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    const ECPublicKey* impl = (const ECPublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    uint8_t* data = NULL;
    EC_KEY* ec;
    int requiredSize;

    /* Check for invalid parameters */
    if (!publicKey || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the EC public key */
    if (!(ec = _GetECKey(impl->pkey)))
        OE_RAISE(OE_FAILURE);

    /* Set the required buffer size */
    if ((requiredSize = i2o_ECPublicKey(ec, NULL)) == 0)
        OE_RAISE(OE_FAILURE);

    /* If buffer is null or not big enough */
    if (!buffer || (*bufferSize < requiredSize))
    {
        *bufferSize = requiredSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Get the key bytes */
    if (!i2o_ECPublicKey(ec, &data))
        OE_RAISE(OE_FAILURE);

    /* Copy to caller's buffer */
    memcpy(buffer, data, requiredSize);
    *bufferSize = requiredSize;

    result = OE_OK;

done:

    if (data)
        free(data);

    return result;
}

OE_Result OE_ECPublicKeyEqual(
    const OE_ECPublicKey* publicKey1,
    const OE_ECPublicKey* publicKey2,
    bool* equal)
{
    OE_Result result = OE_UNEXPECTED;
    const ECPublicKey* impl1 = (const ECPublicKey*)publicKey1;
    const ECPublicKey* impl2 = (const ECPublicKey*)publicKey2;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!_ECPublicKeyValid(impl1) || !_ECPublicKeyValid(impl2) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        const EC_KEY* ec1 = _GetECKey(impl1->pkey);
        const EC_KEY* ec2 = _GetECKey(impl2->pkey);
        const EC_GROUP* group1 = EC_KEY_get0_group(ec1);
        const EC_GROUP* group2 = EC_KEY_get0_group(ec2);
        const EC_POINT* point1 = EC_KEY_get0_public_key(ec1);
        const EC_POINT* point2 = EC_KEY_get0_public_key(ec2);

        /* Compare group and public key point */
        if (EC_GROUP_cmp(group1, group2, NULL) == 0 &&
            EC_POINT_cmp(group1, point1, point2, NULL) == 0)
        {
            *equal = true;
        }
    }

    result = OE_OK;

done:
    return result;
}
