// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <openenclave/bits/ec.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/pem.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../../common/crypto/util.h"
#include "random.h"

// MBEDTLS has no mechanism for determining the size of the PEM buffer ahead
// of time, so we are forced to use a maximum buffer size. This quantity is
// used in MEBEDTLS program that calls mbedtls_pk_write_key_pem.
#define OE_PEM_MAX_BYTES (16 * 1024)

/*
**==============================================================================
**
** Local definitions
**
**==============================================================================
*/

#define OE_EC_PRIVATE_KEY_MAGIC 0xf12c37bb02814eeb

typedef struct _OE_ECPrivateKeyImpl
{
    uint64_t magic;
    mbedtls_pk_context pk;
} OE_ECPrivateKeyImpl;

OE_STATIC_ASSERT(sizeof(OE_ECPrivateKeyImpl) <= sizeof(OE_ECPrivateKey));

OE_INLINE bool _ValidPrivateKeyImpl(const OE_ECPrivateKeyImpl* impl)
{
    return impl && impl->magic == OE_EC_PRIVATE_KEY_MAGIC;
}

OE_INLINE void _InitPrivateKeyImpl(OE_ECPrivateKeyImpl* impl)
{
    impl->magic = OE_EC_PRIVATE_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _FreePrivateKeyImpl(OE_ECPrivateKeyImpl* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(OE_ECPrivateKeyImpl));
    }
}

OE_INLINE void _ClearPrivateKeyImpl(OE_ECPrivateKeyImpl* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(OE_ECPrivateKeyImpl));
}

#define OE_EC_PUBLIC_KEY_MAGIC 0xd7490a56f6504ee6

typedef struct _OE_ECPublicKeyImpl
{
    uint64_t magic;
    mbedtls_pk_context pk;
} OE_ECPublicKeyImpl;

OE_STATIC_ASSERT(sizeof(OE_ECPublicKeyImpl) <= sizeof(OE_ECPublicKey));

OE_INLINE bool _ValidPublicKeyImpl(const OE_ECPublicKeyImpl* impl)
{
    return impl && impl->magic == OE_EC_PUBLIC_KEY_MAGIC;
}

OE_INLINE void _InitPublicKeyImpl(OE_ECPublicKeyImpl* impl)
{
    impl->magic = OE_EC_PUBLIC_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _FreePublicKeyImpl(OE_ECPublicKeyImpl* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(OE_ECPublicKeyImpl));
    }
}

OE_INLINE void _ClearPublicKeyImpl(OE_ECPublicKeyImpl* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(OE_ECPublicKeyImpl));
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

/* Note: a function similar to this one is missing from MBEDTLS */
static int _mbedtls_ecp_keypair_copy(
    mbedtls_ecp_keypair* dest,
    const mbedtls_ecp_keypair* src)
{
    int ret = -1;

    /* Copy group */
    if (mbedtls_ecp_group_copy(&dest->grp, &src->grp) != 0)
        goto done;

    /* Copy secret value */
    if (mbedtls_mpi_copy(&dest->d, &src->d) != 0)
        goto done;

    /* Copy public value */
    if (mbedtls_ecp_copy(&dest->Q, &src->Q) != 0)
        goto done;

    ret = 0;

done:
    return ret;
}

static int _CopyKeyFromKeyPair(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool public)
{
    int ret = -1;
    const mbedtls_pk_info_t* info;
    mbedtls_ecp_keypair* ec;

    /* Check parameters */
    if (!dest || !src)
        goto done;

    /* Lookup the info for this key type */
    if (!(info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)))
        goto done;

    /* Setup the context for this key type */
    if (mbedtls_pk_setup(dest, info) != 0)
        goto done;

    /* Get the context for this key type */
    if (!(ec = dest->pk_ctx))
        goto done;

    /* Initialize the EC key from the source */
    if (_mbedtls_ecp_keypair_copy(ec, mbedtls_pk_ec(*src)) != 0)
        goto done;

    /* If public key, then clear private key fields */
    if (public)
        mbedtls_mpi_free(&ec->d);

    ret = 0;

done:

    return ret;
}

static bool _IsECKey(const mbedtls_pk_context* pk)
{
    if (pk->pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))
        return false;

    return true;
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
    OE_ECPrivateKey* privateKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_ECPrivateKeyImpl* impl = (OE_ECPrivateKeyImpl*)privateKey;

    /* Initialize the key */
    if (impl)
        _InitPrivateKeyImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    OE_CHECK(OE_CheckForNullTerminator(pemData, pemSize));

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(&impl->pk, pemData, pemSize, NULL, 0) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain an EC key */
    if (!_IsECKey(&impl->pk))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _FreePrivateKeyImpl(impl);

    return result;
}

OE_Result OE_ECReadPublicKeyPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPublicKey* publicKey)
{
    OE_ECPublicKeyImpl* impl = (OE_ECPublicKeyImpl*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (impl)
        _InitPublicKeyImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    OE_CHECK(OE_CheckForNullTerminator(pemData, pemSize));

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(&impl->pk, pemData, pemSize) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain an EC key */
    if (!_IsECKey(&impl->pk))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _FreePublicKeyImpl(impl);

    return result;
}

OE_Result OE_ECWritePrivateKeyPEM(
    const OE_ECPrivateKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_ECPrivateKeyImpl* impl = (OE_ECPrivateKeyImpl*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_ValidPrivateKeyImpl(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key to PEM format */
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

OE_Result OE_ECWritePublicKeyPEM(
    const OE_ECPublicKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    OE_ECPublicKeyImpl* impl = (OE_ECPublicKeyImpl*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_ValidPublicKeyImpl(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key to PEM format */
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

OE_Result OE_ECFreePrivateKey(OE_ECPrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        OE_ECPrivateKeyImpl* impl = (OE_ECPrivateKeyImpl*)key;

        if (!_ValidPrivateKeyImpl(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _FreePrivateKeyImpl(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ECFreePublicKey(OE_ECPublicKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        OE_ECPublicKeyImpl* impl = (OE_ECPublicKeyImpl*)key;

        if (!_ValidPublicKeyImpl(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _FreePublicKeyImpl(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ECSign(
    const OE_ECPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const OE_ECPrivateKeyImpl* impl = (const OE_ECPrivateKeyImpl*)privateKey;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t bufferSize = 0;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check parameters */
    if (!_ValidPrivateKeyImpl(impl) || !hashData || !hashSize || !signatureSize)
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

    /* Copy result to output buffer */
    OE_Memcpy(signature, buffer, bufferSize);
    *signatureSize = bufferSize;

    result = OE_OK;

done:

    return result;
}

OE_Result OE_ECVerify(
    const OE_ECPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    const OE_ECPublicKeyImpl* impl = (const OE_ECPublicKeyImpl*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_ValidPublicKeyImpl(impl) || !hashData || !hashSize || !signature ||
        !signatureSize)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Verify the signature */
    if (mbedtls_pk_verify(
            (mbedtls_pk_context*)&impl->pk,
            type,
            hashData,
            hashSize,
            signature,
            signatureSize) != 0)
    {
        OE_RAISE(OE_VERIFY_FAILED);
    }

    result = OE_OK;

done:

    return result;
}

OE_Result OE_ECGenerate(
    OE_ECType type,
    OE_ECPrivateKey* privateKey,
    OE_ECPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_ECPrivateKeyImpl* privateImpl = (OE_ECPrivateKeyImpl*)privateKey;
    OE_ECPublicKeyImpl* publicImpl = (OE_ECPublicKeyImpl*)publicKey;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;
    int curve;
    const char* curveName;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    _ClearPrivateKeyImpl(privateImpl);
    _ClearPublicKeyImpl(publicImpl);

    /* Check for invalid parameters */
    if (!privateImpl || !publicImpl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert curve type to curve name */
    if (!(curveName = _ECTypeToString(type)))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Resolve the curveName parameter to an EC-curve identifier */
    {
        const mbedtls_ecp_curve_info* info;

        if (!(info = mbedtls_ecp_curve_info_from_name(curveName)))
            OE_RAISE(OE_INVALID_PARAMETER);

        curve = info->grp_id;
    }

    /* Get the drbg object */
    if (!(drbg = OE_MBEDTLS_GetDrbg()))
        OE_RAISE(OE_FAILURE);

    /* Create key struct */
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Generate the EC key */
    if (mbedtls_ecp_gen_key(
            curve, mbedtls_pk_ec(pk), mbedtls_ctr_drbg_random, drbg) != 0)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Initialize the private key parameter */
    {
        mbedtls_pk_init(&privateImpl->pk);

        if (_CopyKeyFromKeyPair(&privateImpl->pk, &pk, false) != 0)
        {
            mbedtls_pk_free(&privateImpl->pk);
            OE_RAISE(OE_FAILURE);
        }

        privateImpl->magic = OE_EC_PRIVATE_KEY_MAGIC;
    }

    /* Initialize the public key parameter */
    {
        mbedtls_pk_init(&publicImpl->pk);

        if (_CopyKeyFromKeyPair(&publicImpl->pk, &pk, true) != 0)
        {
            mbedtls_pk_free(&publicImpl->pk);
            OE_RAISE(OE_FAILURE);
        }

        publicImpl->magic = OE_EC_PUBLIC_KEY_MAGIC;
    }

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        OE_ECFreePrivateKey(privateKey);
        OE_ECFreePublicKey(publicKey);
    }

    return result;
}
