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

#define OE_EC_KEY_MAGIC 0xb375208a5590eedb

typedef struct _OE_EC_KEY_IMPL
{
    uint64_t magic;
    mbedtls_pk_context pk;
} OE_EC_KEY_IMPL;

OE_STATIC_ASSERT(sizeof(OE_EC_KEY_IMPL) <= sizeof(OE_EC_KEY));

OE_INLINE bool _ValidImpl(const OE_EC_KEY_IMPL* impl)
{
    return impl && impl->magic == OE_EC_KEY_MAGIC;
}

OE_INLINE void _InitImpl(OE_EC_KEY_IMPL* impl)
{
    impl->magic = OE_EC_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _FreeImpl(OE_EC_KEY_IMPL* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(OE_EC_KEY_IMPL));
    }
}

OE_INLINE void _ClearImpl(OE_EC_KEY_IMPL* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(OE_EC_KEY_IMPL));
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

/* Curve names, indexed by OE_ECType */
static const char* _curveNames[] =
{
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

/*
**==============================================================================
**
** Public EC functions:
**
**==============================================================================
*/

OE_Result OE_ECReadPrivateKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_EC_KEY* privateKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_EC_KEY_IMPL* impl = (OE_EC_KEY_IMPL*)privateKey;

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

OE_Result OE_ECReadPublicKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_EC_KEY* publicKey)
{
    OE_EC_KEY_IMPL* impl = (OE_EC_KEY_IMPL*)publicKey;
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

OE_Result OE_ECWritePrivateKeyPEM(
    const OE_EC_KEY* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_EC_KEY_IMPL* impl = (OE_EC_KEY_IMPL*)key;
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

OE_Result OE_ECWritePublicKeyPEM(
    const OE_EC_KEY* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_EC_KEY_IMPL* impl = (OE_EC_KEY_IMPL*)key;
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

OE_Result OE_ECFree(OE_EC_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_EC_KEY_IMPL* impl = (OE_EC_KEY_IMPL*)key;

    if (!_ValidImpl(impl))
        OE_THROW(OE_INVALID_PARAMETER);

    _FreeImpl(impl);

    result = OE_OK;

OE_CATCH:
    return result;
}

OE_Result OE_ECSign(
    const OE_EC_KEY* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_EC_KEY_IMPL* impl = (const OE_EC_KEY_IMPL*)privateKey;
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

OE_Result OE_ECVerify(
    const OE_EC_KEY* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    const OE_EC_KEY_IMPL* impl = (const OE_EC_KEY_IMPL*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_ValidImpl(impl) || !hashData || !hashSize || !signature ||
        !signatureSize)
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

OE_Result OE_ECGenerate(
    OE_ECType type,
    OE_EC_KEY* privateKey,
    OE_EC_KEY* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_EC_KEY_IMPL* privateImpl = (OE_EC_KEY_IMPL*)privateKey;
    OE_EC_KEY_IMPL* publicImpl = (OE_EC_KEY_IMPL*)publicKey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;
    int curve;
    const char* curveName;

    /* Initialize structures */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    _ClearImpl(privateImpl);
    _ClearImpl(publicImpl);

    /* Check for invalid parameters */
    if (!privateImpl || !publicImpl)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Convert curve type to curve name */
    if (!(curveName = _ECTypeToString(type)))
        OE_THROW(OE_INVALID_PARAMETER);

    /* Resolve the curveName parameter to an EC-curve identifier */
    {
        const mbedtls_ecp_curve_info* info;

        if (!(info = mbedtls_ecp_curve_info_from_name(curveName)))
            OE_THROW(OE_INVALID_PARAMETER);

        curve = info->grp_id;
    }

    /* Set up an entropy source for reseeds below */
    if (mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Create key struct */
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Generate the EC key */
    if (mbedtls_ecp_gen_key(
            curve, mbedtls_pk_ec(pk), mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        OE_THROW(OE_INVALID_PARAMETER);
    }

    /* Initialize the private key parameter */
    {
        OE_EC_KEY_IMPL dummy;
        uint8_t data[OE_PEM_MAX_BYTES];
        size_t size = sizeof(data);

        dummy.magic = OE_EC_KEY_MAGIC;
        dummy.pk = pk;
        OE_TRY(OE_ECWritePrivateKeyPEM((OE_EC_KEY*)&dummy, data, &size));
        pk = dummy.pk;

        OE_TRY(OE_ECReadPrivateKeyPEM(data, size, privateKey));
    }

    /* Initialize the public key parameter */
    {
        OE_EC_KEY_IMPL dummy;
        uint8_t data[OE_PEM_MAX_BYTES];
        size_t size = sizeof(data);

        dummy.magic = OE_EC_KEY_MAGIC;
        dummy.pk = pk;
        OE_TRY(OE_ECWritePublicKeyPEM((OE_EC_KEY*)&dummy, data, &size));
        pk = dummy.pk;

        OE_TRY(OE_ECReadPublicKeyPEM(data, size, publicKey));
    }

    result = OE_OK;

OE_CATCH:

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        if (_ValidImpl(privateImpl))
            OE_ECFree(privateKey);

        if (_ValidImpl(publicImpl))
            OE_ECFree(publicKey);
    }

    return result;
}
