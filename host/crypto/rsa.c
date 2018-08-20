// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "rsa.h"
#include <openenclave/internal/defs.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/utils.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <string.h>
#include "init.h"
#include "key.h"

/* Magic numbers for the RSA key implementation structures */
static const uint64_t _PRIVATE_KEY_MAGIC = 0x7bf635929a714b2c;
static const uint64_t _PUBLIC_KEY_MAGIC = 0x8f8f72170025426d;

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_rsa_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_rsa_private_key_t));

static oe_result_t _privateKeyWritePEMCallback(BIO* bio, EVP_PKEY* pkey)
{
    oe_result_t result = OE_UNEXPECTED;
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

static oe_result_t _GenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    oe_private_key_t* privateKey,
    oe_public_key_t* publicKey)
{
    oe_result_t result = OE_UNEXPECTED;
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
    oe_initialize_openssl();

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
        oe_private_key_init(privateKey, pkeyPrivate, _PRIVATE_KEY_MAGIC);

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
        oe_public_key_init(publicKey, pkeyPublic, _PUBLIC_KEY_MAGIC);

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
        oe_private_key_free(privateKey, _PRIVATE_KEY_MAGIC);
        oe_public_key_free(publicKey, _PUBLIC_KEY_MAGIC);
    }

    return result;
}

static oe_result_t _GetPublicKeyGetModulusOrExponent(
    const oe_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize,
    bool getModulus)
{
    oe_result_t result = OE_UNEXPECTED;
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

static oe_result_t _PublicKeyGetModulus(
    const oe_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyGetModulusOrExponent(
        publicKey, buffer, bufferSize, true);
}

static oe_result_t _PublicKeyGetExponent(
    const oe_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyGetModulusOrExponent(
        publicKey, buffer, bufferSize, false);
}

static oe_result_t _PublicKeyEqual(
    const oe_public_key_t* publicKey1,
    const oe_public_key_t* publicKey2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;
    RSA* rsa1 = NULL;
    RSA* rsa2 = NULL;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!oe_public_key_is_valid(publicKey1, _PUBLIC_KEY_MAGIC) ||
        !oe_public_key_is_valid(publicKey2, _PUBLIC_KEY_MAGIC) || !equal)
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

void oe_rsa_public_key_init(oe_rsa_public_key_t* publicKey, EVP_PKEY* pkey)
{
    return oe_public_key_init(
        (oe_public_key_t*)publicKey, pkey, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* privateKey,
    const uint8_t* pemData,
    size_t pemSize)
{
    return oe_private_key_read_pem(
        pemData,
        pemSize,
        (oe_private_key_t*)privateKey,
        EVP_PKEY_RSA,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_write_pem(
    const oe_rsa_private_key_t* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return oe_private_key_write_pem(
        (const oe_private_key_t*)privateKey,
        pemData,
        pemSize,
        _privateKeyWritePEMCallback,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_read_pem(
    oe_rsa_public_key_t* publicKey,
    const uint8_t* pemData,
    size_t pemSize)
{
    return oe_public_key_read_pem(
        pemData,
        pemSize,
        (oe_public_key_t*)publicKey,
        EVP_PKEY_RSA,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_write_pem(
    const oe_rsa_public_key_t* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)privateKey,
        pemData,
        pemSize,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* privateKey)
{
    return oe_private_key_free(
        (oe_private_key_t*)privateKey, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* publicKey)
{
    return oe_public_key_free((oe_public_key_t*)publicKey, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_sign(
    const oe_rsa_private_key_t* privateKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    return oe_private_key_sign(
        (oe_private_key_t*)privateKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_verify(
    const oe_rsa_public_key_t* publicKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    return oe_public_key_verify(
        (oe_public_key_t*)publicKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_generate_key_pair(
    uint64_t bits,
    uint64_t exponent,
    oe_rsa_private_key_t* privateKey,
    oe_rsa_public_key_t* publicKey)
{
    return _GenerateKeyPair(
        bits,
        exponent,
        (oe_private_key_t*)privateKey,
        (oe_public_key_t*)publicKey);
}

oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _PublicKeyGetModulus(
        (oe_public_key_t*)publicKey, buffer, bufferSize);
}

oe_result_t oe_rsa_public_key_get_exponent(
    const oe_rsa_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _PublicKeyGetExponent(
        (oe_public_key_t*)publicKey, buffer, bufferSize);
}

oe_result_t oe_rsa_public_key_equal(
    const oe_rsa_public_key_t* publicKey1,
    const oe_rsa_public_key_t* publicKey2,
    bool* equal)
{
    return _PublicKeyEqual(
        (oe_public_key_t*)publicKey1, (oe_public_key_t*)publicKey2, equal);
}
