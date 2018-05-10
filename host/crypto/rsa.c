// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "rsa.h"
#include <openenclave/bits/raise.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/bits/utils.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include "init.h"
#include "key.h"

/*
**==============================================================================
**
** Provide definitions needed for key.c and include key.c.
**
**==============================================================================
*/

static const uint64_t _PRIVATE_KEY_MAGIC = 0x7bf635929a714b2c;
static const uint64_t _PUBLIC_KEY_MAGIC = 0x8f8f72170025426d;

/*
**==============================================================================
**
** Definitions below depend on definitions provided by key.c.
**
**==============================================================================
*/

OE_STATIC_ASSERT(sizeof(OE_PublicKey) <= sizeof(OE_RSAPublicKey));
OE_STATIC_ASSERT(sizeof(OE_PublicKey) <= sizeof(OE_RSAPublicKey));

static OE_Result _WriteKey(BIO* bio, EVP_PKEY* pkey)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsa = NULL;

    if (!(rsa = EVP_PKEY_get1_RSA(pkey)))
        OE_RAISE(OE_FAILURE);

    if (!PEM_write_bio_RSAPrivateKey(bio, rsa, NULL, NULL, 0, 0, NULL))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (rsa)
        RSA_free(rsa);

    return result;
}

static OE_Result _GenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    OE_PrivateKey* privateKey,
    OE_PublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsaPrivate = NULL;
    RSA* rsaPublic = NULL;
    EVP_PKEY* pkeyPrivate = NULL;
    EVP_PKEY* pkeyPublic = NULL;

    if (privateKey)
        memset(privateKey, 0, sizeof(*privateKey));

    if (publicKey)
        memset(publicKey, 0, sizeof(*publicKey));

    /* Check parameters */
    if (!privateKey || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check range of bits parameter */
    if (bits > INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check range of exponent */
    if (exponent > ULONG_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Create the public and private RSA keys */
    {
        /* Create the private key */
        if (!(rsaPrivate = RSA_generate_key(bits, exponent, 0, 0)))
            OE_RAISE(OE_FAILURE);

        /* Create the public key */
        if (!(rsaPublic = RSAPublicKey_dup(rsaPrivate)))
            OE_RAISE(OE_FAILURE);
    }

    /* Create the PKEY private key wrapper */
    {
        /* Create the private key structure */
        if (!(pkeyPrivate = EVP_PKEY_new()))
            OE_RAISE(OE_FAILURE);

        /* Initialize the private key from the generated key pair */
        if (!EVP_PKEY_assign_RSA(pkeyPrivate, rsaPrivate))
            OE_RAISE(OE_FAILURE);

        /* Initialize the private key */
        OE_PrivateKeyInit(privateKey, pkeyPrivate, _PRIVATE_KEY_MAGIC);

        /* Keep these from being freed below */
        rsaPrivate = NULL;
        pkeyPrivate = NULL;
    }

    /* Create the PKEY public key wrapper */
    {
        /* Create the public key structure */
        if (!(pkeyPublic = EVP_PKEY_new()))
            OE_RAISE(OE_FAILURE);

        /* Initialize the public key from the generated key pair */
        if (!EVP_PKEY_assign_RSA(pkeyPublic, rsaPublic))
            OE_RAISE(OE_FAILURE);

        /* Initialize the public key */
        OE_PublicKeyInit(publicKey, pkeyPublic, _PUBLIC_KEY_MAGIC);

        /* Keep these from being freed below */
        rsaPublic = NULL;
        pkeyPublic = NULL;
    }

    result = OE_OK;

done:

    if (rsaPrivate)
        RSA_free(rsaPrivate);

    if (rsaPublic)
        RSA_free(rsaPublic);

    if (pkeyPrivate)
        EVP_PKEY_free(pkeyPrivate);

    if (pkeyPublic)
        EVP_PKEY_free(pkeyPublic);

    if (result != OE_OK)
    {
        OE_PrivateKeyFree(privateKey, _PRIVATE_KEY_MAGIC);
        OE_PublicKeyFree(publicKey, _PUBLIC_KEY_MAGIC);
    }

    return result;
}

static OE_Result _GetPublicKeyGetModulusOrExponent(
    const OE_PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize,
    bool getModulus)
{
    OE_Result result = OE_UNEXPECTED;
    size_t requiredSize;
    const BIGNUM* bn;
    RSA* rsa = NULL;

    /* Check for invalid parameters */
    if (!publicKey || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then bufferSize must be zero */
    if (!buffer && *bufferSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get RSA key */
    if (!(rsa = EVP_PKEY_get1_RSA(publicKey->pkey)))
        OE_RAISE(OE_FAILURE);

    /* Select modulus or exponent */
    bn = getModulus ? rsa->n : rsa->e;

    /* Determine the required size in bytes */
    {
        int n = BN_num_bytes(bn);

        if (n <= 0)
            OE_RAISE(OE_FAILURE);

        /* Add one leading byte for the leading zero byte */
        requiredSize = (size_t)n;
    }

    /* If buffer is null or not big enough */
    if (!buffer || (*bufferSize < requiredSize))
    {
        *bufferSize = requiredSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy key bytes to the caller's buffer */
    if (!BN_bn2bin(bn, buffer))
        OE_RAISE(OE_FAILURE);

    *bufferSize = requiredSize;

    result = OE_OK;

done:

    if (rsa)
        RSA_free(rsa);

    return result;
}

static OE_Result _PublicKeyGetModulus(
    const OE_PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyGetModulusOrExponent(
        publicKey, buffer, bufferSize, true);
}

static OE_Result _PublicKeyGetExponent(
    const OE_PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyGetModulusOrExponent(
        publicKey, buffer, bufferSize, false);
}

static OE_Result _PublicKeyEqual(
    const OE_PublicKey* publicKey1,
    const OE_PublicKey* publicKey2,
    bool* equal)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsa1 = NULL;
    RSA* rsa2 = NULL;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!OE_PublicKeyIsValid(publicKey1, _PUBLIC_KEY_MAGIC) ||
        !OE_PublicKeyIsValid(publicKey2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(rsa1 = EVP_PKEY_get1_RSA(publicKey1->pkey)))
        OE_RAISE(OE_INVALID_PARAMETER);

    if (!(rsa2 = EVP_PKEY_get1_RSA(publicKey2->pkey)))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Compare modulus and exponent */
    if (BN_cmp(rsa1->n, rsa2->n) == 0 && BN_cmp(rsa1->e, rsa2->e) == 0)
        *equal = true;

    result = OE_OK;

done:

    if (rsa1)
        RSA_free(rsa1);

    if (rsa2)
        RSA_free(rsa2);

    return result;
}

void OE_RSAPublicKeyInit(OE_RSAPublicKey* publicKey, EVP_PKEY* pkey)
{
    return OE_PublicKeyInit((OE_PublicKey*)publicKey, pkey, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_RSAPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPrivateKey* privateKey)
{
    return OE_PrivateKeyReadPEM(
        pemData,
        pemSize,
        (OE_PrivateKey*)privateKey,
        EVP_PKEY_RSA,
        _PRIVATE_KEY_MAGIC);
}

OE_Result OE_RSAPrivateKeyWritePEM(
    const OE_RSAPrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return OE_PrivateKeyWritePEM(
        (const OE_PrivateKey*)privateKey,
        pemData,
        pemSize,
        _WriteKey,
        _PRIVATE_KEY_MAGIC);
}

OE_Result OE_RSAPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPublicKey* publicKey)
{
    return OE_PublicKeyReadPEM(
        pemData,
        pemSize,
        (OE_PublicKey*)publicKey,
        EVP_PKEY_RSA,
        _PUBLIC_KEY_MAGIC);
}

OE_Result OE_RSAPublicKeyWritePEM(
    const OE_RSAPublicKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return OE_PublicKeyWritePEM(
        (const OE_PublicKey*)privateKey, pemData, pemSize, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_RSAPrivateKeyFree(OE_RSAPrivateKey* privateKey)
{
    return OE_PrivateKeyFree((OE_PrivateKey*)privateKey, _PRIVATE_KEY_MAGIC);
}

OE_Result OE_RSAPublicKeyFree(OE_RSAPublicKey* publicKey)
{
    return OE_PublicKeyFree((OE_PublicKey*)publicKey, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_RSAPrivateKeySign(
    const OE_RSAPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    return OE_PrivateKeySign(
        (OE_PrivateKey*)privateKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize,
        _PRIVATE_KEY_MAGIC);
}

OE_Result OE_RSAPublicKeyVerify(
    const OE_RSAPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    return OE_PublicKeyVerify(
        (OE_PublicKey*)publicKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize,
        _PUBLIC_KEY_MAGIC);
}

OE_Result OE_RSAGenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    OE_RSAPrivateKey* privateKey,
    OE_RSAPublicKey* publicKey)
{
    return _GenerateKeyPair(
        bits, exponent, (OE_PrivateKey*)privateKey, (OE_PublicKey*)publicKey);
}

OE_Result OE_RSAPublicKeyGetModulus(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _PublicKeyGetModulus((OE_PublicKey*)publicKey, buffer, bufferSize);
}

OE_Result OE_RSAPublicKeyGetExponent(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _PublicKeyGetExponent((OE_PublicKey*)publicKey, buffer, bufferSize);
}

OE_Result OE_RSAPublicKeyEqual(
    const OE_RSAPublicKey* publicKey1,
    const OE_RSAPublicKey* publicKey2,
    bool* equal)
{
    return _PublicKeyEqual(
        (OE_PublicKey*)publicKey1, (OE_PublicKey*)publicKey2, equal);
}
