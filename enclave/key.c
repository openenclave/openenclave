// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "key.h"
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/hash.h>
#include <openenclave/bits/raise.h>
#include "pem.h"

typedef OE_Result (*OE_CopyKey)(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields);

bool OE_PrivateKeyIsValid(const OE_PrivateKey* privateKey, uint64_t magic)
{
    return privateKey && privateKey->magic == magic;
}

OE_Result OE_PrivateKeyInit(
    OE_PrivateKey* privateKey,
    const mbedtls_pk_context* pk,
    OE_CopyKey copyKey,
    uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;

    if (!privateKey || (pk && !copyKey) || (copyKey && !pk))
        OE_RAISE(OE_INVALID_PARAMETER);

    privateKey->magic = 0;

    if (pk && copyKey)
        OE_CHECK(copyKey(&privateKey->pk, pk, true));
    else
        mbedtls_pk_init(&privateKey->pk);

    privateKey->magic = magic;

    result = OE_OK;

done:
    return result;
}

void OE_PrivateKeyRelease(OE_PrivateKey* privateKey, uint64_t magic)
{
    if (OE_PrivateKeyIsValid(privateKey, magic))
    {
        mbedtls_pk_free(&privateKey->pk);
        OE_Memset(privateKey, 0, sizeof(OE_PrivateKey));
    }
}

bool OE_PublicKeyIsValid(const OE_PublicKey* publicKey, uint64_t magic)
{
    return publicKey && publicKey->magic == magic;
}

OE_Result OE_PublicKeyInit(
    OE_PublicKey* publicKey,
    const mbedtls_pk_context* pk,
    OE_CopyKey copyKey,
    uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;

    if (!publicKey || (pk && !copyKey) || (copyKey && !pk))
        OE_RAISE(OE_INVALID_PARAMETER);

    publicKey->magic = 0;

    if (pk && copyKey)
        OE_CHECK(copyKey(&publicKey->pk, pk, false));
    else
        mbedtls_pk_init(&publicKey->pk);

    publicKey->magic = magic;

    result = OE_OK;

done:
    return result;
}

void OE_PublicKeyRelease(OE_PublicKey* publicKey, uint64_t magic)
{
    if (OE_PublicKeyIsValid(publicKey, magic))
    {
        mbedtls_pk_free(&publicKey->pk);
        OE_Memset(publicKey, 0, sizeof(OE_PublicKey));
    }
}

/*
**==============================================================================
**
** _MapHashType()
**
**==============================================================================
*/

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
    return MBEDTLS_MD_NONE;
}

/*
**==============================================================================
**
** Public functions:
**
**==============================================================================
*/

OE_Result OE_PrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_PrivateKey* privateKey,
    mbedtls_pk_type_t keyType,
    uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (privateKey)
        OE_CHECK(OE_PrivateKeyInit(privateKey, NULL, NULL, magic));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !privateKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(&privateKey->pk, pemData, pemSize, NULL, 0) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain this type of key */
    if (privateKey->pk.pk_info != mbedtls_pk_info_from_type(keyType))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        OE_PrivateKeyRelease(privateKey, magic);

    return result;
}

OE_Result OE_PrivateKeyWritePEM(
    const OE_PrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize,
    uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!OE_PrivateKeyIsValid(privateKey, magic) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
    if (mbedtls_pk_write_key_pem(
            (mbedtls_pk_context*)&privateKey->pk, buf, sizeof(buf)) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

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

OE_Result OE_PublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_PublicKey* publicKey,
    mbedtls_pk_type_t keyType,
    uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (publicKey)
        OE_CHECK(OE_PublicKeyInit(publicKey, NULL, NULL, magic));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(&publicKey->pk, pemData, pemSize) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain an EC key */
    if (publicKey->pk.pk_info != mbedtls_pk_info_from_type(keyType))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        OE_PublicKeyRelease(publicKey, magic);

    return result;
}

OE_Result OE_PublicKeyWritePEM(
    const OE_PublicKey* publicKey,
    uint8_t* pemData,
    size_t* pemSize,
    uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!OE_PublicKeyIsValid(publicKey, magic) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key to PEM format */
    if (mbedtls_pk_write_pubkey_pem(
            (mbedtls_pk_context*)&publicKey->pk, buf, sizeof(buf)) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

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

OE_Result OE_PrivateKeyFree(OE_PrivateKey* privateKey, uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;

    if (privateKey)
    {
        if (!OE_PrivateKeyIsValid(privateKey, magic))
            OE_RAISE(OE_INVALID_PARAMETER);

        OE_PrivateKeyRelease(privateKey, magic);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_PublicKeyFree(OE_PublicKey* publicKey, uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;

    if (publicKey)
    {
        if (!OE_PublicKeyIsValid(publicKey, magic))
            OE_RAISE(OE_INVALID_PARAMETER);

        OE_PublicKeyRelease(publicKey, magic);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_PrivateKeySign(
    const OE_PrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize,
    uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t bufferSize = 0;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check parameters */
    if (!OE_PrivateKeyIsValid(privateKey, magic) || !hashData || !hashSize ||
        !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Sign the message. Note that bufferSize is an output parameter only.
    // MEBEDTLS provides no way to determine the size of the buffer up front.
    if (mbedtls_pk_sign(
            (mbedtls_pk_context*)&privateKey->pk,
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

OE_Result OE_PublicKeyVerify(
    const OE_PublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize,
    uint64_t magic)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!OE_PublicKeyIsValid(publicKey, magic) || !hashData || !hashSize ||
        !signature || !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Verify the signature */
    if (mbedtls_pk_verify(
            (mbedtls_pk_context*)&publicKey->pk,
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
