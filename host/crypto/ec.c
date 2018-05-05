// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <openenclave/bits/raise.h>
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

static const uint64_t PRIVATE_KEY_MAGIC = 0x19a751419ae04bbc;
static const uint64_t PUBLIC_KEY_MAGIC = 0xb1d39580c1f14c02;

typedef OE_ECPrivateKey PrivateKey;
typedef OE_ECPublicKey PublicKey;

typedef EC_KEY KEYTYPE;

static const __typeof(EVP_PKEY_RSA) EVP_PKEY_KEYTYPE = EVP_PKEY_EC;

static EC_KEY* EVP_PKEY_get1_KEYTYPE(EVP_PKEY* pkey)
{
    return EVP_PKEY_get1_EC_KEY(pkey);
}

static void KEYTYPE_free(EC_KEY* key)
{
    EC_KEY_free(key);
}

static int PEM_write_bio_KEYTYPEPrivateKey(
    BIO* bp,
    EC_KEY* x,
    const EVP_CIPHER* enc,
    unsigned char* kstr,
    int klen,
    pem_password_cb* cb,
    void* u)
{
    return PEM_write_bio_ECPrivateKey(bp, x, enc, kstr, klen, cb, u);
}

#include "key.c"

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

void OE_ECPublicKeyInit(PublicKey* publicKey, EVP_PKEY* pkey)
{
    return _PublicKeyInit(publicKey, pkey);
}

OE_Result OE_ECPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPrivateKey* privateKey)
{
    return _PrivateKeyReadPEM(pemData, pemSize, privateKey);
}

OE_Result OE_ECPrivateKeyWritePEM(
    const OE_ECPrivateKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    return _PrivateKeyWritePEM(key, pemData, pemSize);
}

OE_Result OE_ECPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPublicKey* publicKey)
{
    return _PublicKeyReadPEM(pemData, pemSize, publicKey);
}

OE_Result OE_ECPublicKeyWritePEM(
    const OE_ECPublicKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    return _PublicKeyWritePEM(key, pemData, pemSize);
}

OE_Result OE_ECPrivateKeyFree(OE_ECPrivateKey* key)
{
    return _PrivateKeyFree(key);
}

OE_Result OE_ECPublicKeyFree(OE_ECPublicKey* key)
{
    return _PublicKeyFree(key);
}

OE_Result OE_ECPrivateKeySign(
    const OE_ECPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    return _PrivateKeySign(
        privateKey, hashType, hashData, hashSize, signature, signatureSize);
}

OE_Result OE_ECPublicKeyVerify(
    const OE_ECPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    return _PublicKeyVerify(
        publicKey, hashType, hashData, hashSize, signature, signatureSize);
}

OE_Result OE_ECGenerateKeyPair(
    OE_ECType type,
    OE_ECPrivateKey* privateKey,
    OE_ECPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    PrivateKeyImpl* privateImpl = (PrivateKeyImpl*)privateKey;
    PublicKeyImpl* publicImpl = (PublicKeyImpl*)publicKey;
    int nid;
    EC_KEY* key = NULL;
    EVP_PKEY* pkey = NULL;
    BIO* bio = NULL;
    const char nullTerminator = '\0';
    const char* curveName;

    _PrivateKeyClear(privateImpl);
    _PublicKeyClear(publicImpl);

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
    const PublicKeyImpl* impl = (const PublicKeyImpl*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    uint8_t* data = NULL;
    EC_KEY* ec = NULL;
    int requiredSize;

    /* Check for invalid parameters */
    if (!publicKey || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the EC public key */
    if (!(ec = EVP_PKEY_get1_EC_KEY(impl->pkey)))
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

    if (ec)
        EC_KEY_free(ec);

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
    const PublicKeyImpl* impl1 = (const PublicKeyImpl*)publicKey1;
    const PublicKeyImpl* impl2 = (const PublicKeyImpl*)publicKey2;
    EC_KEY* ec1 = NULL;
    EC_KEY* ec2 = NULL;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!_PublicKeyValid(impl1) || !_PublicKeyValid(impl2) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        ec1 = EVP_PKEY_get1_EC_KEY(impl1->pkey);
        ec2 = EVP_PKEY_get1_EC_KEY(impl2->pkey);
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

    if (ec1)
        EC_KEY_free(ec1);

    if (ec2)
        EC_KEY_free(ec2);

    return result;
}
