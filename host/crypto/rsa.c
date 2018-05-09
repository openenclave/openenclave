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

static const uint64_t PRIVATE_KEY_MAGIC = 0x7bf635929a714b2c;
static const uint64_t PUBLIC_KEY_MAGIC = 0x8f8f72170025426d;

static const __typeof(EVP_PKEY_RSA) EVP_PKEY_KEYTYPE = EVP_PKEY_RSA;

typedef RSA KEYTYPE;

static KEYTYPE* EVP_PKEY_get1_KEYTYPE(EVP_PKEY* pkey)
{
    return EVP_PKEY_get1_RSA(pkey);
}

static void KEYTYPE_free(KEYTYPE* key)
{
    RSA_free(key);
}

static int PEM_write_bio_KEYTYPEPrivateKey(
    BIO* bp,
    KEYTYPE* x,
    const EVP_CIPHER* enc,
    unsigned char* kstr,
    int klen,
    pem_password_cb* cb,
    void* u)
{
    return PEM_write_bio_RSAPrivateKey(bp, x, enc, kstr, klen, cb, u);
}

#include "key.c"

OE_STATIC_ASSERT(sizeof(PublicKey) <= sizeof(OE_RSAPublicKey));
OE_STATIC_ASSERT(sizeof(PublicKey) <= sizeof(OE_RSAPublicKey));

static OE_Result _GenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    PrivateKey* privateKey,
    PublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* key = NULL;
    EVP_PKEY* pkey = NULL;
    BIO* bio = NULL;
    const char nullTerminator = '\0';

    if (privateKey)
        memset(privateKey, 0, sizeof(*privateKey));

    if (publicKey)
        memset(publicKey, 0, sizeof(*publicKey));

    /* Check parameters */
    if (!privateKey || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    OE_InitializeOpenSSL();

    /* Generate an RSA key pair */
    if (!(key = RSA_generate_key(bits, exponent, 0, 0)))
        OE_RAISE(OE_FAILURE);

    /* Create the private key structure */
    if (!(pkey = EVP_PKEY_new()))
        OE_RAISE(OE_FAILURE);

    /* Initialize the private key from the generated key pair */
    if (!EVP_PKEY_assign_RSA(pkey, key))
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

        if (_PrivateKeyReadPEM((uint8_t*)mem->data, mem->length, privateKey) !=
            OE_OK)
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

        if (_PublicKeyReadPEM((uint8_t*)mem->data, mem->length, publicKey) !=
            OE_OK)
        {
            OE_RAISE(OE_FAILURE);
        }

        BIO_free(bio);
        bio = NULL;
    }

    result = OE_OK;

done:

    if (key)
        RSA_free(key);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (bio)
        BIO_free(bio);

    if (result != OE_OK)
    {
        _PrivateKeyFree(privateKey);
        _PublicKeyFree(publicKey);
    }

    return result;
}

static OE_Result _GetPublicKeyGetModulusOrExponent(
    const PublicKey* publicKey,
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
    const PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyGetModulusOrExponent(
        publicKey, buffer, bufferSize, true);
}

static OE_Result _PublicKeyGetExponent(
    const PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyGetModulusOrExponent(
        publicKey, buffer, bufferSize, false);
}

static OE_Result _PublicKeyEqual(
    const PublicKey* publicKey1,
    const PublicKey* publicKey2,
    bool* equal)
{
    OE_Result result = OE_UNEXPECTED;
    RSA* rsa1 = NULL;
    RSA* rsa2 = NULL;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!_PublicKeyValid(publicKey1) || !_PublicKeyValid(publicKey2) || !equal)
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

ALIAS(_PublicKeyInit, OE_RSAPublicKeyInit);
ALIAS(_PrivateKeyReadPEM, OE_RSAPrivateKeyReadPEM);
ALIAS(_PrivateKeyWritePEM, OE_RSAPrivateKeyWritePEM);
ALIAS(_PublicKeyReadPEM, OE_RSAPublicKeyReadPEM);
ALIAS(_PublicKeyWritePEM, OE_RSAPublicKeyWritePEM);
ALIAS(_PrivateKeyFree, OE_RSAPrivateKeyFree);
ALIAS(_PublicKeyFree, OE_RSAPublicKeyFree);
ALIAS(_PrivateKeySign, OE_RSAPrivateKeySign);
ALIAS(_PublicKeyVerify, OE_RSAPublicKeyVerify);
ALIAS(_GenerateKeyPair, OE_RSAGenerateKeyPair);
ALIAS(_PublicKeyGetModulus, OE_RSAPublicKeyGetModulus);
ALIAS(_PublicKeyGetExponent, OE_RSAPublicKeyGetExponent);
ALIAS(_PublicKeyEqual, OE_RSAPublicKeyEqual);
