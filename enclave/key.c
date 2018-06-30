// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/internal/corelibc/string.h>
#include "key.h"
#include <openenclave/internal/hash.h>
#include <openenclave/internal/raise.h>
#include "pem.h"

typedef oe_result_t (*oe_copy_key)(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields);

bool oe_private_key_is_valid(const oe_private_key_t* privateKey, uint64_t magic)
{
    return privateKey && privateKey->magic == magic;
}

oe_result_t oe_private_key_init(
    oe_private_key_t* privateKey,
    const mbedtls_pk_context* pk,
    oe_copy_key copyKey,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

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

void oe_private_key_release(oe_private_key_t* privateKey, uint64_t magic)
{
    if (oe_private_key_is_valid(privateKey, magic))
    {
        mbedtls_pk_free(&privateKey->pk);
        oe_memset(privateKey, 0, sizeof(oe_private_key_t));
    }
}

bool oe_public_key_is_valid(const oe_public_key_t* publicKey, uint64_t magic)
{
    return publicKey && publicKey->magic == magic;
}

oe_result_t oe_public_key_init(
    oe_public_key_t* publicKey,
    const mbedtls_pk_context* pk,
    oe_copy_key copyKey,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

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

void oe_public_key_release(oe_public_key_t* publicKey, uint64_t magic)
{
    if (oe_public_key_is_valid(publicKey, magic))
    {
        mbedtls_pk_free(&publicKey->pk);
        oe_memset(publicKey, 0, sizeof(oe_public_key_t));
    }
}

/*
**==============================================================================
**
** _MapHashType()
**
**==============================================================================
*/

static mbedtls_md_type_t _MapHashType(oe_hash_type_t md)
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
** Public functions:
**
**==============================================================================
*/

oe_result_t oe_private_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_private_key_t* privateKey,
    mbedtls_pk_type_t keyType,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Initialize the key */
    if (privateKey)
        OE_CHECK(oe_private_key_init(privateKey, NULL, NULL, magic));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !privateKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (oe_strnlen((const char*)pemData, pemSize) != pemSize - 1)
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
        oe_private_key_release(privateKey, magic);

    return result;
}

oe_result_t oe_private_key_write_pem(
    const oe_private_key_t* privateKey,
    uint8_t* pemData,
    size_t* pemSize,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!oe_private_key_is_valid(privateKey, magic) || !pemSize)
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
        size_t size = oe_strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        oe_memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_public_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_public_key_t* publicKey,
    mbedtls_pk_type_t keyType,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Initialize the key */
    if (publicKey)
        OE_CHECK(oe_public_key_init(publicKey, NULL, NULL, magic));

    /* Check parameters */
    if (!pemData || pemSize == 0 || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (oe_strnlen((const char*)pemData, pemSize) != pemSize - 1)
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
        oe_public_key_release(publicKey, magic);

    return result;
}

oe_result_t oe_public_key_write_pem(
    const oe_public_key_t* publicKey,
    uint8_t* pemData,
    size_t* pemSize,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!oe_public_key_is_valid(publicKey, magic) || !pemSize)
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
        size_t size = oe_strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        oe_memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_private_key_free(oe_private_key_t* privateKey, uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (privateKey)
    {
        if (!oe_private_key_is_valid(privateKey, magic))
            OE_RAISE(OE_INVALID_PARAMETER);

        oe_private_key_release(privateKey, magic);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_public_key_free(oe_public_key_t* publicKey, uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (publicKey)
    {
        if (!oe_public_key_is_valid(publicKey, magic))
            OE_RAISE(OE_INVALID_PARAMETER);

        oe_public_key_release(publicKey, magic);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_private_key_sign(
    const oe_private_key_t* privateKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t bufferSize = 0;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check parameters */
    if (!oe_private_key_is_valid(privateKey, magic) || !hashData || !hashSize ||
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
    oe_memcpy(signature, buffer, bufferSize);
    *signatureSize = bufferSize;

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_public_key_verify(
    const oe_public_key_t* publicKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!oe_public_key_is_valid(publicKey, magic) || !hashData || !hashSize ||
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
