// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <openenclave/bits/ec.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/bits/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../util.h"

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

/*
**==============================================================================
**
** Public EC functions:
**
**==============================================================================
*/

OE_Result OE_RSAReadPrivateKeyFromPEM(
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
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    OE_TRY(OE_CheckForNullTerminator(pemData, pemSize));

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(&impl->pk, pemData, pemSize, NULL, 0) != 0)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

OE_CATCH:

    if (result != OE_OK)
        _FreeImpl(impl);

    return result;
}

OE_Result OE_RSAReadPublicKeyFromPEM(
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
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    OE_TRY(OE_CheckForNullTerminator(pemData, pemSize));

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(&impl->pk, pemData, pemSize) != 0)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

OE_CATCH:

    if (result != OE_OK)
        _FreeImpl(impl);

    return result;
}

OE_Result OE_RSAWritePrivateKeyToPEM(
    const OE_RSA_KEY* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_ValidImpl(impl) || !pemSize)
        OE_THROW(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
    if (mbedtls_pk_write_key_pem(&impl->pk, buf, sizeof(buf)) != 0)
        OE_THROW(OE_FAILURE);

    /* Handle case where caller's buffer is too small */
    {
        size_t size = OE_Strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_THROW(OE_BUFFER_TOO_SMALL);
        }

        OE_Memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

OE_Result OE_RSAWritePublicKeyToPEM(
    const OE_RSA_KEY* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_ValidImpl(impl) || !pemSize)
        OE_THROW(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
    if (mbedtls_pk_write_pubkey_pem(&impl->pk, buf, sizeof(buf)) != 0)
        OE_THROW(OE_FAILURE);

    /* Handle case where caller's buffer is too small */
    {
        size_t size = OE_Strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_THROW(OE_BUFFER_TOO_SMALL);
        }

        OE_Memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

OE_Result OE_RSAFree(OE_RSA_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;

    if (!_ValidImpl(impl))
        OE_THROW(OE_INVALID_PARAMETER);

    _FreeImpl(impl);

    result = OE_OK;

OE_CATCH:
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
        OE_THROW(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_THROW(OE_INVALID_PARAMETER);

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
        OE_THROW(OE_FAILURE);
    }

    // If signature buffer parameter is too small:
    if (*signatureSize < bufferSize)
    {
        *signatureSize = bufferSize;
        OE_THROW(OE_BUFFER_TOO_SMALL);
    }

    /* Copy buffer onto signature buffer */
    OE_Memcpy(signature, buffer, bufferSize);
    *signatureSize = bufferSize;

    result = OE_OK;

OE_CATCH:

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
    if (!_ValidImpl(impl) || !hashData || !hashSize || !signature || !signatureSize)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Verify the signature */
    if (mbedtls_pk_verify(
            (mbedtls_pk_context*)&impl->pk,
            type,
            hashData,
            hashSize,
            signature,
            signatureSize) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    result = OE_OK;

OE_CATCH:

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
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;

    /* Initialize structures */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    _ClearImpl(privateImpl);
    _ClearImpl(publicImpl);

    /* Check for invalid parameters */
    if (!privateImpl || !publicImpl)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Check range of bits and exponent parameters */
    if (bits > OE_MAX_UINT || exponent > OE_MAX_INT)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Set up an entropy source for reseeds below */
    if (mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    /* Create key struct */
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    /* Generate the RSA key */
    if (mbedtls_rsa_gen_key(
            mbedtls_pk_rsa(pk),
            mbedtls_ctr_drbg_random,
            &ctr_drbg,
            bits,
            exponent) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    /* Initialize the private key parameter */
    {
        OE_RSA_KEY_IMPL dummy;
        uint8_t data[OE_PEM_MAX_BYTES];
        size_t size = sizeof(data);

        dummy.magic = OE_RSA_KEY_MAGIC;
        dummy.pk = pk;
        OE_TRY(OE_RSAWritePrivateKeyToPEM((OE_RSA_KEY*)&dummy, data, &size));
        pk = dummy.pk;

        OE_TRY(OE_RSAReadPrivateKeyFromPEM(data, size, privateKey));
    }

    /* Initialize the private key parameter */
    {
        OE_RSA_KEY_IMPL dummy;
        uint8_t data[OE_PEM_MAX_BYTES];
        size_t size = sizeof(data);

        dummy.magic = OE_RSA_KEY_MAGIC;
        dummy.pk = pk;
        OE_TRY(OE_RSAWritePublicKeyToPEM((OE_RSA_KEY*)&dummy, data, &size));
        pk = dummy.pk;

        OE_TRY(OE_RSAReadPublicKeyFromPEM(data, size, privateKey));
    }

    result = OE_OK;

OE_CATCH:

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
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
