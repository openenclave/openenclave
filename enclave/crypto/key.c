// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include "key.h"
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/crypto/hash.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include <string.h>
#include "pem.h"

typedef oe_result_t (*oe_copy_key)(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copy_private_fields);

bool oe_private_key_is_valid(
    const oe_private_key_t* private_key,
    uint64_t magic)
{
    return private_key && private_key->magic == magic;
}

oe_result_t oe_private_key_init(
    oe_private_key_t* private_key,
    const mbedtls_pk_context* pk,
    oe_copy_key copy_key,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!private_key || (pk && !copy_key) || (copy_key && !pk))
        OE_RAISE(OE_INVALID_PARAMETER);

    private_key->magic = 0;

    if (pk && copy_key)
        OE_CHECK(copy_key(&private_key->pk, pk, true));
    else
        mbedtls_pk_init(&private_key->pk);

    private_key->magic = magic;

    result = OE_OK;

done:
    return result;
}

void oe_private_key_release(oe_private_key_t* private_key, uint64_t magic)
{
    if (oe_private_key_is_valid(private_key, magic))
    {
        mbedtls_pk_free(&private_key->pk);
        oe_secure_zero_fill(private_key, sizeof(oe_private_key_t));
    }
}

bool oe_public_key_is_valid(const oe_public_key_t* public_key, uint64_t magic)
{
    return public_key && public_key->magic == magic;
}

oe_result_t oe_public_key_init(
    oe_public_key_t* public_key,
    const mbedtls_pk_context* pk,
    oe_copy_key copy_key,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (!public_key || (pk && !copy_key) || (copy_key && !pk))
        OE_RAISE(OE_INVALID_PARAMETER);

    public_key->magic = 0;

    if (pk && copy_key)
        OE_CHECK(copy_key(&public_key->pk, pk, false));
    else
        mbedtls_pk_init(&public_key->pk);

    public_key->magic = magic;

    result = OE_OK;

done:
    return result;
}

void oe_public_key_release(oe_public_key_t* public_key, uint64_t magic)
{
    if (oe_public_key_is_valid(public_key, magic))
    {
        mbedtls_pk_free(&public_key->pk);
        oe_secure_zero_fill(public_key, sizeof(oe_public_key_t));
    }
}

/*
**==============================================================================
**
** _map_hash_type()
**
**==============================================================================
*/

static mbedtls_md_type_t _map_hash_type(oe_hash_type_t md)
{
    switch (md)
    {
        case OE_HASH_TYPE_SHA256:
            return MBEDTLS_MD_SHA256;
        case OE_HASH_TYPE_SHA512:
            return MBEDTLS_MD_SHA512;
        case __OE_HASH_TYPE_MAX:
            return MBEDTLS_MD_NONE;
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
    const uint8_t* pem_data,
    size_t pem_size,
    oe_private_key_t* private_key,
    mbedtls_pk_type_t key_type,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    int rc = 0;

    /* Initialize the key */
    if (private_key)
        OE_CHECK(oe_private_key_init(private_key, NULL, NULL, magic));

    /* Check parameters */
    if (!pem_data || pem_size == 0 || !private_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    rc = mbedtls_pk_parse_key(&private_key->pk, pem_data, pem_size, NULL, 0);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

    /* Fail if PEM data did not contain this type of key */
    if (private_key->pk.pk_info != mbedtls_pk_info_from_type(key_type))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        oe_private_key_release(private_key, magic);

    return result;
}

oe_result_t oe_private_key_write_pem(
    const oe_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_PEM_MAX_BYTES];
    int rc = 0;

    /* Check parameters */
    if (!oe_private_key_is_valid(private_key, magic) || !pem_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pem_data && *pem_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
    rc = mbedtls_pk_write_key_pem(
        (mbedtls_pk_context*)&private_key->pk, buf, sizeof(buf));
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

    /* Handle case where caller's buffer is too small */
    {
        size_t size = strlen((char*)buf) + 1;

        if (*pem_size < size)
        {
            *pem_size = size;
            OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
        }

        OE_CHECK(oe_memcpy_s(pem_data, *pem_size, buf, size));
        *pem_size = size;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_public_key_read_pem(
    const uint8_t* pem_data,
    size_t pem_size,
    oe_public_key_t* public_key,
    mbedtls_pk_type_t key_type,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    int rc = 0;

    /* Initialize the key */
    if (public_key)
        OE_CHECK(oe_public_key_init(public_key, NULL, NULL, magic));

    /* Check parameters */
    if (!pem_data || pem_size == 0 || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pem_size-1 non-zero characters followed by zero-terminator */
    if (strnlen((const char*)pem_data, pem_size) != pem_size - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    rc = mbedtls_pk_parse_public_key(&public_key->pk, pem_data, pem_size);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

    /* Fail if PEM data did not contain an EC key */
    if (public_key->pk.pk_info != mbedtls_pk_info_from_type(key_type))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        oe_public_key_release(public_key, magic);

    return result;
}

oe_result_t oe_public_key_write_pem(
    const oe_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buf[OE_PEM_MAX_BYTES];
    int rc = 0;

    /* Check parameters */
    if (!oe_public_key_is_valid(public_key, magic) || !pem_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pem_data && *pem_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key to PEM format */
    rc = mbedtls_pk_write_pubkey_pem(
        (mbedtls_pk_context*)&public_key->pk, buf, sizeof(buf));
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

    /* Handle case where caller's buffer is too small */
    {
        size_t size = strlen((char*)buf) + 1;

        if (*pem_size < size)
        {
            *pem_size = size;
            OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
        }

        OE_CHECK(oe_memcpy_s(pem_data, *pem_size, buf, size));
        *pem_size = size;
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_private_key_free(oe_private_key_t* private_key, uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (private_key)
    {
        if (!oe_private_key_is_valid(private_key, magic))
            OE_RAISE_NO_TRACE(OE_INVALID_PARAMETER);

        oe_private_key_release(private_key, magic);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_public_key_free(oe_public_key_t* public_key, uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;

    if (public_key)
    {
        if (!oe_public_key_is_valid(public_key, magic))
            OE_RAISE_NO_TRACE(OE_INVALID_PARAMETER);

        oe_public_key_release(public_key, magic);
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_private_key_sign(
    const oe_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t buffer_size = 0;
    mbedtls_md_type_t type = _map_hash_type(hash_type);
    int rc = 0;

    if (type == MBEDTLS_MD_NONE)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check parameters */
    if (!oe_private_key_is_valid(private_key, magic) || !hash_data ||
        !hash_size || !signature_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Sign the message. Note that buffer_size is an output parameter only.
    // MEBEDTLS provides no way to determine the size of the buffer up front.
    rc = mbedtls_pk_sign(
        (mbedtls_pk_context*)&private_key->pk,
        type,
        hash_data,
        hash_size,
        buffer,
        &buffer_size,
        NULL,
        NULL);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

    // If signature buffer parameter is too small:
    if (*signature_size < buffer_size)
    {
        *signature_size = buffer_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy result to output buffer */
    OE_CHECK(oe_memcpy_s(signature, *signature_size, buffer, buffer_size));
    *signature_size = buffer_size;

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_public_key_verify(
    const oe_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size,
    uint64_t magic)
{
    oe_result_t result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _map_hash_type(hash_type);
    int rc = 0;

    /* Check for null parameters */
    if (!oe_public_key_is_valid(public_key, magic) || !hash_data ||
        !hash_size || !signature || !signature_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Verify the signature */
    rc = mbedtls_pk_verify(
        (mbedtls_pk_context*)&public_key->pk,
        type,
        hash_data,
        hash_size,
        signature,
        signature_size);
    if (rc != 0)
        OE_RAISE_MSG(OE_VERIFY_FAILED, "rc = 0x%x", rc * (-1));

    result = OE_OK;

done:

    return result;
}
