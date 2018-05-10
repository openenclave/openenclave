// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "rsa.h"
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include "pem.h"
#include "random.h"
#include "key.h"

static uint64_t _PRIVATE_KEY_MAGIC = 0xd48de5bae3994b41;
static uint64_t _PUBLIC_KEY_MAGIC = 0x713600af058c447a;

OE_STATIC_ASSERT(sizeof(OE_PrivateKey) <= sizeof(OE_RSAPrivateKey));
OE_STATIC_ASSERT(sizeof(OE_PublicKey) <= sizeof(OE_RSAPublicKey));

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
    const OE_PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize,
    bool getModulus)
{
    OE_Result result = OE_UNEXPECTED;
    size_t requiredSize;
    mbedtls_rsa_context* rsa;
    const mbedtls_mpi* mpi;

    /* Check for invalid parameters */
    if (!OE_PublicKeyValid(publicKey, _PUBLIC_KEY_MAGIC) || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then bufferSize must be zero */
    if (!buffer && *bufferSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the RSA context */
    if (!(rsa = publicKey->pk.pk_ctx))
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

static OE_Result _GenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    OE_PrivateKey* privateKey,
    OE_PublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    if (privateKey)
        OE_Memset(privateKey, 0, sizeof(*privateKey));

    if (publicKey)
        OE_Memset(publicKey, 0, sizeof(*publicKey));

    /* Check for invalid parameters */
    if (!privateKey || !publicKey)
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
    OE_CHECK(OE_PrivateKeyInit(privateKey, &pk, _CopyKey, _PRIVATE_KEY_MAGIC));

    /* Initialize the public key parameter */
    OE_CHECK(OE_PublicKeyInit(publicKey, &pk, _CopyKey, _PUBLIC_KEY_MAGIC));

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        if (OE_PrivateKeyValid(privateKey, _PRIVATE_KEY_MAGIC))
            OE_PrivateKeyFree(privateKey, _PRIVATE_KEY_MAGIC);

        if (OE_PublicKeyValid(publicKey, _PUBLIC_KEY_MAGIC))
            OE_PublicKeyFree(publicKey, _PUBLIC_KEY_MAGIC);
    }

    return result;
}

OE_Result OE_PublicKeyGetModulus(
    const OE_PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyModulusOrExponent(publicKey, buffer, bufferSize, true);
}

OE_Result OE_PublicKeyGetExponent(
    const OE_PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyModulusOrExponent(publicKey, buffer, bufferSize, false);
}

static OE_Result OE_PublicKeyEqual(
    const OE_PublicKey* publicKey1,
    const OE_PublicKey* publicKey2,
    bool* equal)
{
    OE_Result result = OE_UNEXPECTED;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!OE_PublicKeyValid(publicKey1, _PUBLIC_KEY_MAGIC) || !OE_PublicKeyValid(publicKey2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Compare the exponent and modulus */
    {
        const mbedtls_rsa_context* rsa1 = publicKey1->pk.pk_ctx;
        const mbedtls_rsa_context* rsa2 = publicKey2->pk.pk_ctx;

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

OE_Result OE_RSAPublicKeyInit(
    OE_RSAPublicKey* publicKey,
    const mbedtls_pk_context* pk)
{
    return OE_PublicKeyInit((OE_PublicKey*)publicKey, pk, _CopyKey, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_RSAPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPrivateKey* privateKey)
{
    return OE_PrivateKeyReadPEM(pemData, pemSize, (OE_PrivateKey*)privateKey,
        MBEDTLS_PK_RSA, _PRIVATE_KEY_MAGIC);
}

OE_Result OE_RSAPrivateKeyWritePEM(
    const OE_RSAPrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return OE_PrivateKeyWritePEM((const OE_PrivateKey*)privateKey, pemData, pemSize, _PRIVATE_KEY_MAGIC);
}

OE_Result OE_RSAPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPublicKey* privateKey)
{
    return OE_PublicKeyReadPEM(pemData, pemSize, (OE_PublicKey*)privateKey,
        MBEDTLS_PK_RSA, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_RSAPublicKeyWritePEM(
    const OE_RSAPublicKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return OE_PublicKeyWritePEM((const OE_PublicKey*)privateKey, pemData, pemSize, _PUBLIC_KEY_MAGIC);
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
    return _GenerateKeyPair(bits, exponent, (OE_PrivateKey*)privateKey, (OE_PublicKey*)publicKey);
}

OE_Result OE_RSAPublicKeyGetModulus(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return OE_PublicKeyGetModulus((OE_PublicKey*)publicKey, buffer, bufferSize);
}

OE_Result OE_RSAPublicKeyGetExponent(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return OE_PublicKeyGetExponent((OE_PublicKey*)publicKey, buffer, bufferSize);
}

OE_Result OE_RSAPublicKeyEqual(
    const OE_RSAPublicKey* publicKey1,
    const OE_RSAPublicKey* publicKey2,
    bool* equal)
{
    return OE_PublicKeyEqual((OE_PublicKey*)publicKey1, (OE_PublicKey*)publicKey2,
        equal);
}
