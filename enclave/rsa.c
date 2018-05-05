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

static const uint64_t PRIVATE_KEY_MAGIC = 0xd48de5bae3994b41;
static const uint64_t PUBLIC_KEY_MAGIC = 0x713600af058c447a;
typedef OE_RSAPrivateKey PrivateKey;
typedef OE_RSAPublicKey PublicKey;
static const mbedtls_pk_type_t MBEDTLS_PK_KEYTYPE = MBEDTLS_PK_RSA;
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
    const PublicKeyImpl* impl = (const PublicKeyImpl*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    size_t requiredSize;
    mbedtls_rsa_context* rsa;
    const mbedtls_mpi* mpi;

    /* Check for invalid parameters */
    if (!_PublicKeyImplValid(impl) || !bufferSize)
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

OE_WEAK_ALIAS(_PublicKeyImplInitFrom, OE_RSAPublicKeyInitFrom);
OE_WEAK_ALIAS(_PrivateKeyReadPEM, OE_RSAPrivateKeyReadPEM);
OE_WEAK_ALIAS(_PrivateKeyWritePEM, OE_RSAPrivateKeyWritePEM);
OE_WEAK_ALIAS(_PublicKeyReadPEM, OE_RSAPublicKeyReadPEM);
OE_WEAK_ALIAS(_PublicKeyWritePEM, OE_RSAPublicKeyWritePEM);
OE_WEAK_ALIAS(_PrivateKeyFree, OE_RSAPrivateKeyFree);
OE_WEAK_ALIAS(_PublicKeyFree, OE_RSAPublicKeyFree);
OE_WEAK_ALIAS(_PrivateKeySign, OE_RSAPrivateKeySign);
OE_WEAK_ALIAS(_PublicKeyVerify, OE_RSAPublicKeyVerify);

OE_Result OE_RSAGenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    OE_RSAPrivateKey* privateKey,
    OE_RSAPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    PrivateKeyImpl* privateImpl = (PrivateKeyImpl*)privateKey;
    PublicKeyImpl* publicImpl = (PublicKeyImpl*)publicKey;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    if (privateImpl)
        OE_Memset(privateImpl, 0, sizeof(*privateImpl));

    if (publicImpl)
        OE_Memset(publicImpl, 0, sizeof(*publicImpl));

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
    OE_CHECK(_PrivateKeyImplInitFrom(privateImpl, &pk));

    /* Initialize the public key parameter */
    OE_CHECK(OE_RSAPublicKeyInitFrom(publicKey, &pk));

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        if (_PrivateKeyImplValid(privateImpl))
            _PrivateKeyImplFree(privateImpl);

        if (_PublicKeyImplValid(publicImpl))
            _PublicKeyImplFree(publicImpl);
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
    const PublicKeyImpl* impl1 = (const PublicKeyImpl*)publicKey1;
    const PublicKeyImpl* impl2 = (const PublicKeyImpl*)publicKey2;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!_PublicKeyImplValid(impl1) || !_PublicKeyImplValid(impl2) || !equal)
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
