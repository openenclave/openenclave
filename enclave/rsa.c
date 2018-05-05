// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "rsa.h"
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include "pem.h"
#include "random.h"

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

static OE_Result _CopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields);

#define PRIVATE_KEY_MAGIC 0xd48de5bae3994b41
#define PUBLIC_KEY_MAGIC 0x713600af058c447a
#define PRIVATE_KEY OE_RSAPrivateKey
#define PUBLIC_KEY OE_RSAPublicKey
#define IS_KEY_FUNCTION OE_IsRSAKey
#include "key.c"

static OE_Result _CopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields)
{
    OE_Result result = OE_UNEXPECTED;
    const mbedtls_pk_info_t* info;
    mbedtls_rsa_context* rsa;

    if (dest)
        mbedtls_pk_init(dest);

    /* Check for invalid parameters */
    if (!dest || !src)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Lookup the RSA info */
    if (!(info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))
        OE_RAISE(OE_WRONG_TYPE);

    /* If not an RSA key */
    if (src->pk_info != info)
        OE_RAISE(OE_FAILURE);

    /* Setup the context for this key type */
    if (mbedtls_pk_setup(dest, info) != 0)
        OE_RAISE(OE_FAILURE);

    /* Get the context for this key type */
    if (!(rsa = dest->pk_ctx))
        OE_RAISE(OE_FAILURE);

    /* Initialize the RSA key from the source */
    if (mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(*src)) != 0)
        OE_RAISE(OE_FAILURE);

    /* If not a private key, then clear private key fields */
    if (!copyPrivateFields)
    {
        mbedtls_mpi_free(&rsa->D);
        mbedtls_mpi_free(&rsa->P);
        mbedtls_mpi_free(&rsa->Q);
        mbedtls_mpi_free(&rsa->DP);
        mbedtls_mpi_free(&rsa->DQ);
        mbedtls_mpi_free(&rsa->QP);
        mbedtls_mpi_free(&rsa->RN);
        mbedtls_mpi_free(&rsa->RP);
        mbedtls_mpi_free(&rsa->RQ);
        mbedtls_mpi_free(&rsa->Vi);
        mbedtls_mpi_free(&rsa->Vf);
    }

    result = OE_OK;

done:

    if (result != OE_OK)
        mbedtls_pk_free(dest);

    return result;
}

static OE_Result _GetPublicKeyModulusOrExponent(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize,
    bool getModulus)
{
    const PublicKey* impl = (const PublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    size_t requiredSize;
    mbedtls_rsa_context* rsa;
    const mbedtls_mpi* mpi;

    /* Check for invalid parameters */
    if (!_PublicKeyValid(impl) || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then bufferSize must be zero */
    if (!buffer && *bufferSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the RSA context */
    if (!(rsa = impl->pk.pk_ctx))
        OE_RAISE(OE_FAILURE);

    /* Pick modulus or exponent */
    if (!(mpi = getModulus ? &rsa->N : &rsa->E))
        OE_RAISE(OE_FAILURE);

    /* Determine the required size in bytes */
    requiredSize = mbedtls_mpi_size(mpi);

    /* If buffer is null or not big enough */
    if (!buffer || (*bufferSize < requiredSize))
    {
        *bufferSize = requiredSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy key bytes to the caller's buffer */
    if (mbedtls_mpi_write_binary(mpi, buffer, requiredSize) != 0)
        OE_RAISE(OE_FAILURE);

    *bufferSize = requiredSize;

    result = OE_OK;

done:

    return result;
}

/*
**==============================================================================
**
** Public functions:
**
**==============================================================================
*/

OE_Result OE_RSAPublicKeyInitFrom(
    OE_RSAPublicKey* publicKey,
    const mbedtls_pk_context* pk)
{
    return _PublicKeyInitFrom(publicKey, pk);
}

OE_Result OE_RSAPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPrivateKey* privateKey)
{
    return _PrivateKeyReadPEM(pemData, pemSize, privateKey);
}

OE_Result OE_RSAPrivateKeyWritePEM(
    const OE_RSAPrivateKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    return _PrivateKeyWritePEM(key, pemData, pemSize);
}

OE_Result OE_RSAPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPublicKey* publicKey)
{
    return _PublicKeyReadPEM(pemData, pemSize, publicKey);
}

OE_Result OE_RSAPublicKeyWritePEM(
    const OE_RSAPublicKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    return _PublicKeyWritePEM(key, pemData, pemSize);
}

OE_Result OE_RSAPrivateKeyFree(OE_RSAPrivateKey* key)
{
    return _PrivateKeyFree(key);
}

OE_Result OE_RSAPublicKeyFree(OE_RSAPublicKey* key)
{
    return _PublicKeyFree(key);
}

OE_Result OE_RSAPrivateKeySign(
    const OE_RSAPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    return _PrivateKeySign(
        privateKey, hashType, hashData, hashSize, signature, signatureSize);
}

OE_Result OE_RSAPublicKeyVerify(
    const OE_RSAPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    return _PublicKeyVerify(
        publicKey, hashType, hashData, hashSize, signature, signatureSize);
}

OE_Result OE_RSAGenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    OE_RSAPrivateKey* privateKey,
    OE_RSAPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    PrivateKey* privateImpl = (PrivateKey*)privateKey;
    PublicKey* publicImpl = (PublicKey*)publicKey;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    _PrivateKeyClear(privateImpl);
    _PublicKeyClear(publicImpl);

    /* Check for invalid parameters */
    if (!privateImpl || !publicImpl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check range of bits and exponent parameters */
    if (bits > OE_MAX_UINT || exponent > OE_MAX_INT)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the random number generator */
    if (!(drbg = OE_MBEDTLS_GetDrbg()))
        OE_RAISE(OE_FAILURE);

    /* Create key struct */
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
        OE_RAISE(OE_FAILURE);

    /* Generate the RSA key */
    if (mbedtls_rsa_gen_key(
            mbedtls_pk_rsa(pk),
            mbedtls_ctr_drbg_random,
            drbg,
            bits,
            exponent) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* Initialize the private key parameter */
    OE_CHECK(_PrivateKeyInitFrom(privateImpl, &pk));

    /* Initialize the public key parameter */
    OE_CHECK(OE_RSAPublicKeyInitFrom(publicKey, &pk));

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        if (_PrivateKeyValid(privateImpl))
            _PrivateKeyRelease(privateImpl);

        if (_PublicKeyValid(publicImpl))
            _PublicKeyRelease(publicImpl);
    }

    return result;
}
OE_Result OE_RSAPublicKeyGetModulus(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyModulusOrExponent(publicKey, buffer, bufferSize, true);
}

OE_Result OE_RSAPublicKeyGetExponent(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyModulusOrExponent(publicKey, buffer, bufferSize, false);
}

OE_Result OE_RSAPublicKeyEqual(
    const OE_RSAPublicKey* publicKey1,
    const OE_RSAPublicKey* publicKey2,
    bool* equal)
{
    OE_Result result = OE_UNEXPECTED;
    const PublicKey* impl1 = (const PublicKey*)publicKey1;
    const PublicKey* impl2 = (const PublicKey*)publicKey2;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!_PublicKeyValid(impl1) || !_PublicKeyValid(impl2) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Compare the exponent and modulus */
    {
        const mbedtls_rsa_context* rsa1 = impl1->pk.pk_ctx;
        const mbedtls_rsa_context* rsa2 = impl2->pk.pk_ctx;

        if (!rsa1 || !rsa2)
            OE_RAISE(OE_INVALID_PARAMETER);

        if (mbedtls_mpi_cmp_mpi(&rsa1->N, &rsa2->N) == 0 &&
            mbedtls_mpi_cmp_mpi(&rsa1->E, &rsa2->E) == 0)
        {
            *equal = true;
        }
    }

    result = OE_OK;

done:
    return result;
}
