// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../util.h"
#include "random.h"

// MBEDTLS has no mechanism for determining the size of the PEM buffer ahead
// of time, so we are forced to use a maximum buffer size.
#define OE_PEM_MAX_BYTES (16 * 1024)

/*
**==============================================================================
**
** Local definitions
**
**==============================================================================
*/

#define OE_RSA_KEY_MAGIC 0xb375208a5590eedb

typedef struct _OE_RSA_KEY_IMPL
{
    uint64_t magic;
    mbedtls_pk_context pk;
} OE_RSA_KEY_IMPL;

OE_STATIC_ASSERT(sizeof(OE_RSA_KEY_IMPL) <= sizeof(OE_RSA_KEY));

OE_INLINE bool _ValidImpl(const OE_RSA_KEY_IMPL* impl)
{
    return impl && impl->magic == OE_RSA_KEY_MAGIC;
}

OE_INLINE void _InitImpl(OE_RSA_KEY_IMPL* impl)
{
    impl->magic = OE_RSA_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _FreeImpl(OE_RSA_KEY_IMPL* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(OE_RSA_KEY_IMPL));
    }
}

OE_INLINE void _ClearImpl(OE_RSA_KEY_IMPL* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(OE_RSA_KEY_IMPL));
}

static mbedtls_md_type_t _MapHashType(OE_HashType md)
{
    switch (md)
    {
        case OE_HASH_TYPE_SHA256:
            return MBEDTLS_MD_SHA256;
        case OE_HASH_TYPE_SHA512:
            return MBEDTLS_MD_SHA512;
    }

    /* Unreachable */
    return 0;
}

static int _CopyKeyFromKeyPair(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool public)
{
    int ret = -1;
    const mbedtls_pk_info_t* info;
    mbedtls_rsa_context* rsa;

    /* Check parameters */
    if (!dest || !src)
        goto done;

    /* Lookup the RSA info */
    if (!(info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))
        goto done;

    /* Setup the context for this key type */
    if (mbedtls_pk_setup(dest, info) != 0)
        goto done;

    /* Get the context for this key type */
    if (!(rsa = dest->pk_ctx))
        goto done;

    /* Initialize the RSA key from the source */
    if (mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(*src)) != 0)
        goto done;

    /* If public key, then clear private key fields */
    if (public)
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

    ret = 0;

done:

    return ret;
}

/*
**==============================================================================
**
** Public EC functions:
**
**==============================================================================
*/

OE_Result OE_RSAReadPrivateKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSA_KEY* privateKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)privateKey;

    /* Initialize the key */
    if (impl)
        _InitImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    OE_CHECK(OE_CheckForNullTerminator(pemData, pemSize));

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(&impl->pk, pemData, pemSize, NULL, 0) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _FreeImpl(impl);

    return result;
}

OE_Result OE_RSAReadPublicKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSA_KEY* publicKey)
{
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (impl)
        _InitImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    OE_CHECK(OE_CheckForNullTerminator(pemData, pemSize));

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(&impl->pk, pemData, pemSize) != 0)
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _FreeImpl(impl);

    return result;
}

OE_Result OE_RSAWritePrivateKeyPEM(
    const OE_RSA_KEY* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_ValidImpl(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
    if (mbedtls_pk_write_key_pem(&impl->pk, buf, sizeof(buf)) != 0)
        OE_RAISE(OE_FAILURE);

    /* Handle case where caller's buffer is too small */
    {
        size_t size = OE_Strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        OE_Memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_RSAWritePublicKeyPEM(
    const OE_RSA_KEY* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_ValidImpl(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
    if (mbedtls_pk_write_pubkey_pem(&impl->pk, buf, sizeof(buf)) != 0)
        OE_RAISE(OE_FAILURE);

    /* Handle case where caller's buffer is too small */
    {
        size_t size = OE_Strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        OE_Memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_RSAFree(OE_RSA_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;

        if (!_ValidImpl(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _FreeImpl(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_RSASign(
    const OE_RSA_KEY* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_RSA_KEY_IMPL* impl = (const OE_RSA_KEY_IMPL*)privateKey;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t bufferSize = 0;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check parameters */
    if (!_ValidImpl(impl) || !hashData || !hashSize || !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Sign the message. Note that bufferSize is an output parameter only.
    // MEBEDTLS provides no way to determine the size of the buffer up front.
    if (mbedtls_pk_sign(
            (mbedtls_pk_context*)&impl->pk,
            type,
            hashData,
            hashSize,
            buffer,
            &bufferSize,
            NULL,
            NULL) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    // If signature buffer parameter is too small:
    if (*signatureSize < bufferSize)
    {
        *signatureSize = bufferSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy buffer onto signature buffer */
    OE_Memcpy(signature, buffer, bufferSize);
    *signatureSize = bufferSize;

    result = OE_OK;

done:

    return result;
}

OE_Result OE_RSAVerify(
    const OE_RSA_KEY* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    const OE_RSA_KEY_IMPL* impl = (const OE_RSA_KEY_IMPL*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_ValidImpl(impl) || !hashData || !hashSize || !signature ||
        !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Verify the signature */
    if (mbedtls_pk_verify(
            (mbedtls_pk_context*)&impl->pk,
            type,
            hashData,
            hashSize,
            signature,
            signatureSize) != 0)
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
    OE_RSA_KEY* privateKey,
    OE_RSA_KEY* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* privateImpl = (OE_RSA_KEY_IMPL*)privateKey;
    OE_RSA_KEY_IMPL* publicImpl = (OE_RSA_KEY_IMPL*)publicKey;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    _ClearImpl(privateImpl);
    _ClearImpl(publicImpl);

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
    {
        mbedtls_pk_init(&privateImpl->pk);

        if (_CopyKeyFromKeyPair(&privateImpl->pk, &pk, false) != 0)
        {
            mbedtls_pk_free(&privateImpl->pk);
            OE_RAISE(OE_FAILURE);
        }

        privateImpl->magic = OE_RSA_KEY_MAGIC;
    }

    /* Initialize the public key parameter */
    {
        mbedtls_pk_init(&publicImpl->pk);

        if (_CopyKeyFromKeyPair(&publicImpl->pk, &pk, true) != 0)
        {
            mbedtls_pk_free(&publicImpl->pk);
            OE_RAISE(OE_FAILURE);
        }

        publicImpl->magic = OE_RSA_KEY_MAGIC;
    }

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        if (_ValidImpl(privateImpl))
            OE_RSAFree(privateKey);

        if (_ValidImpl(publicImpl))
            OE_RSAFree(publicKey);
    }

    return result;
}
