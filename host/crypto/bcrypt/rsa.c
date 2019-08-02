// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/utils.h>

#include "../magic.h"
#include "../rsa.h"
#include "bcrypt.h"

/*
 * Note that these structures were copied from the linux crypto/key.h file.
 * They can be consolidated once more crypto code is ported to Windows.
 */
typedef struct oe_private_key_t
{
    uint64_t magic;
    BCRYPT_KEY_HANDLE pkey;
} oe_private_key_t;

typedef struct oe_public_key_t
{
    uint64_t magic;
    BCRYPT_KEY_HANDLE pkey;
} oe_public_key_t;

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_rsa_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_rsa_private_key_t));

/*
 * These *key_is_valid functions are copied from the linux crypto/key.c. These
 * can be consolidated once more crypto code is ported to Windows.
 */
bool oe_private_key_is_valid(const oe_private_key_t* impl)
{
    return impl && impl->magic == OE_RSA_PRIVATE_KEY_MAGIC && impl->pkey;
}

bool oe_public_key_is_valid(const oe_public_key_t* impl)
{
    return impl && impl->magic == OE_RSA_PUBLIC_KEY_MAGIC && impl->pkey;
}

static oe_result_t _rsa_pem_to_der(
    const uint8_t* pem_data,
    size_t pem_size,
    uint8_t** der_data,
    DWORD* der_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* der_local = NULL;
    DWORD der_local_size = 0;
    BOOL success;

    if (!pem_data || !der_data | !der_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    if (pem_size == 0 || pem_size > MAXDWORD)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Subtract 1, since BCrypt doesn't count the null terminator.*/
    pem_size--;

    success = CryptStringToBinaryA(
        (const char*)pem_data,
        (DWORD)pem_size,
        CRYPT_STRING_BASE64HEADER,
        NULL,
        &der_local_size,
        NULL,
        NULL);

    /* With a null buffer, CryptStringToA returns true and sets the size. */
    if (!success)
        OE_RAISE(OE_CRYPTO_ERROR);

    der_local = (uint8_t*)malloc(der_local_size);
    if (der_local == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    success = CryptStringToBinaryA(
        (const char*)pem_data,
        (DWORD)pem_size,
        CRYPT_STRING_BASE64HEADER,
        der_local,
        &der_local_size,
        NULL,
        NULL);

    if (!success)
        OE_RAISE(OE_CRYPTO_ERROR);

    *der_data = der_local;
    *der_size = der_local_size;
    result = OE_OK;
    der_local = NULL;

done:
    if (der_local)
    {
        oe_secure_zero_fill(der_local, der_local_size);
        free(der_local);
        der_local_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* der_data = NULL;
    DWORD der_size = 0;
    uint8_t* rsa_blob = NULL;
    DWORD rsa_blob_size = 0;
    BCRYPT_KEY_HANDLE handle = NULL;

    if (!private_key || !pem_data)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Step 1: Convert PEM to DER. */
    OE_CHECK(_rsa_pem_to_der(pem_data, pem_size, &der_data, &der_size));

    /* Step 2: Decode DER to Crypt object. */
    {
        BOOL success = CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            CNG_RSA_PRIVATE_KEY_BLOB,
            der_data,
            der_size,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL,
            &rsa_blob,
            &rsa_blob_size);

        if (!success)
            OE_RAISE(OE_CRYPTO_ERROR);
    }

    /* Step 3: Convert the Crypt object to a BCrypt Key. */
    {
        NTSTATUS status = BCryptImportKeyPair(
            BCRYPT_RSA_ALG_HANDLE,
            NULL,
            BCRYPT_RSAPRIVATE_BLOB,
            &handle,
            rsa_blob,
            rsa_blob_size,
            0);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE(OE_CRYPTO_ERROR);
    }

    /* Step 4: Convery BCrypt Handle to OE type. */
    {
        oe_private_key_t* pkey = (oe_private_key_t*)private_key;
        pkey->magic = OE_RSA_PRIVATE_KEY_MAGIC;
        pkey->pkey = handle;
        handle = NULL;
    }

    result = OE_OK;

done:
    if (handle)
        BCryptDestroyKey(handle);

    /*
     * Make sure to zero out all confidential (private key) data.
     * Note that rsa_blob must be freed with LocalFree and before der_data
     * due to constraints in CryptObjectDecodeEx.
     */
    if (rsa_blob)
    {
        oe_secure_zero_fill(rsa_blob, rsa_blob_size);
        LocalFree(rsa_blob);
        rsa_blob_size = 0;
    }

    if (der_data)
    {
        oe_secure_zero_fill(der_data, der_size);
        free(der_data);
        der_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* private_key)
{
    oe_result_t result = OE_UNEXPECTED;

    if (private_key)
    {
        oe_private_key_t* impl = (oe_private_key_t*)private_key;

        /* Check parameter */
        if (!oe_private_key_is_valid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        BCryptDestroyKey(impl->pkey);

        /* Clear the fields of the implementation */
        oe_secure_zero_fill(impl, sizeof(*impl));
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_rsa_private_key_sign(
    const oe_rsa_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_private_key_t* impl = (const oe_private_key_t*)private_key;

    /* Check for null parameters and invalid sizes. */
    if (!oe_private_key_is_valid(impl) || !hash_data || !hash_size ||
        hash_size > MAXDWORD || !signature_size || *signature_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        ULONG sig_size;
        NTSTATUS status;
        BCRYPT_PKCS1_PADDING_INFO info;
        uint8_t hash_data_copy[64];

        /* Check for support hash types and correct sizes. */
        switch (hash_type)
        {
            case OE_HASH_TYPE_SHA256:
                if (hash_size != 32)
                    OE_RAISE(OE_INVALID_PARAMETER);
                info.pszAlgId = BCRYPT_SHA256_ALGORITHM;
                break;
            case OE_HASH_TYPE_SHA512:
                if (hash_size != 64)
                    OE_RAISE(OE_INVALID_PARAMETER);
                info.pszAlgId = BCRYPT_SHA512_ALGORITHM;
                break;
            default:
                OE_RAISE(OE_INVALID_PARAMETER);
        }

        /* Need to make a copy since BCryptSignHash's pbInput isn't const. */
        OE_CHECK(oe_memcpy_s(
            hash_data_copy, sizeof(hash_data_copy), hash_data, hash_size));

        /* Determine the size of the signature; fail if buffer is too small */
        status = BCryptSignHash(
            impl->pkey,
            &info,
            hash_data_copy,
            (ULONG)hash_size,
            NULL,
            0,
            &sig_size,
            BCRYPT_PAD_PKCS1);

        if (sig_size > *signature_size)
        {
            *signature_size = sig_size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        /*
         * Perform the signing now. Note that we use the less secure PKCS1
         * signature padding because Intel requires it. However, this is
         * fine since there are no known attacks on PKCS1 signature
         * verification.
         */
        status = BCryptSignHash(
            impl->pkey,
            &info,
            hash_data_copy,
            (ULONG)hash_size,
            signature,
            sig_size,
            &sig_size,
            BCRYPT_PAD_PKCS1);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE(OE_CRYPTO_ERROR);

        *signature_size = sig_size;
    }

    result = OE_OK;

done:
    return result;
}

static oe_result_t _get_public_rsa_blob_info(
    BCRYPT_KEY_HANDLE key,
    uint8_t** buffer,
    ULONG* buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    NTSTATUS status;
    uint8_t* buffer_local = NULL;
    ULONG buffer_local_size = 0;
    BCRYPT_RSAKEY_BLOB* key_header;

    if (!key || !buffer || !buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    status = BCryptExportKey(
        key, NULL, BCRYPT_RSAPUBLIC_BLOB, NULL, 0, &buffer_local_size, 0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE(OE_CRYPTO_ERROR);

    buffer_local = (uint8_t*)malloc(buffer_local_size);
    if (buffer_local == NULL)
        OE_RAISE(OE_OUT_OF_MEMORY);

    status = BCryptExportKey(
        key,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        buffer_local,
        buffer_local_size,
        &buffer_local_size,
        0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Sanity check to ensure we get modulus and public exponent. */
    key_header = (BCRYPT_RSAKEY_BLOB*)buffer_local;
    if (key_header->cbPublicExp == 0 || key_header->cbModulus == 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    *buffer = buffer_local;
    *buffer_size = buffer_local_size;
    buffer_local = NULL;
    result = OE_OK;

done:
    if (buffer_local)
    {
        oe_secure_zero_fill(buffer_local, buffer_local_size);
        free(buffer_local);
        buffer_local_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_get_public_key_from_private(
    const oe_rsa_private_key_t* private_key,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* impl = (oe_private_key_t*)private_key;
    uint8_t* keybuf = NULL;
    ULONG keybuf_size;

    if (!oe_private_key_is_valid(impl) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_get_public_rsa_blob_info(impl->pkey, &keybuf, &keybuf_size));

    /*
     * Export the key blob to a public key. Note that the private key blob has
     * the modulus and the exponent already, so we can just use it to import
     * the public key.
     */
    {
        NTSTATUS status;
        BCRYPT_KEY_HANDLE public_key_handle;

        status = BCryptImportKeyPair(
            BCRYPT_RSA_ALG_HANDLE,
            NULL,
            BCRYPT_RSAPUBLIC_BLOB,
            &public_key_handle,
            keybuf,
            keybuf_size,
            0);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE(OE_CRYPTO_ERROR);

        ((oe_public_key_t*)public_key)->magic = OE_RSA_PUBLIC_KEY_MAGIC;
        ((oe_public_key_t*)public_key)->pkey = public_key_handle;
    }

    result = OE_OK;

done:
    if (keybuf)
    {
        oe_secure_zero_fill(keybuf, keybuf_size);
        free(keybuf);
        keybuf_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    uint8_t* keybuf = NULL;
    ULONG keybuf_size;
    BCRYPT_RSAKEY_BLOB* keyblob;

    /* Check for null parameters and invalid sizes. */
    if (!oe_public_key_is_valid(impl) || !buffer_size ||
        *buffer_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If buffer is null, then buffer_size must be zero */
    if (!buffer && *buffer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_get_public_rsa_blob_info(impl->pkey, &keybuf, &keybuf_size));

    keyblob = (BCRYPT_RSAKEY_BLOB*)keybuf;
    if (keyblob->cbModulus > *buffer_size)
    {
        *buffer_size = keyblob->cbModulus;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * A RSA public key BCrypt blob has the following format in contiguous
     * memory:
     *   BCRYPT_RSAKEY_BLOB struct
     *   PublicExponent[cbPublicExp] in big endian
     *   Modulus[cbModulus] in big endian
     */
    OE_CHECK(oe_memcpy_s(
        buffer,
        *buffer_size,
        keybuf + sizeof(*keyblob) + keyblob->cbPublicExp,
        keyblob->cbModulus));

    *buffer_size = keyblob->cbModulus;
    result = OE_OK;

done:
    if (keybuf)
    {
        oe_secure_zero_fill(keybuf, keybuf_size);
        free(keybuf);
        keybuf_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_public_key_get_exponent(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    uint8_t* keybuf = NULL;
    ULONG keybuf_size;
    BCRYPT_RSAKEY_BLOB* keyblob;

    /* Check for null parameters and invalid sizes. */
    if (!oe_public_key_is_valid(impl) || !buffer_size ||
        *buffer_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If buffer is null, then buffer_size must be zero */
    if (!buffer && *buffer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_get_public_rsa_blob_info(impl->pkey, &keybuf, &keybuf_size));

    keyblob = (BCRYPT_RSAKEY_BLOB*)keybuf;
    if (keyblob->cbPublicExp > *buffer_size)
    {
        *buffer_size = keyblob->cbPublicExp;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * A RSA public key BCrypt blob has the following format in contiguous
     * memory:
     *   BCRYPT_RSAKEY_BLOB struct
     *   PublicExponent[cbPublicExp] in big endian
     *   Modulus[cbModulus] in big endian
     */
    OE_CHECK(oe_memcpy_s(
        buffer, *buffer_size, keybuf + sizeof(*keyblob), keyblob->cbPublicExp));

    *buffer_size = keyblob->cbPublicExp;
    result = OE_OK;

done:
    if (keybuf)
    {
        oe_secure_zero_fill(keybuf, keybuf_size);
        free(keybuf);
        keybuf_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;

    if (public_key)
    {
        oe_public_key_t* impl = (oe_public_key_t*)public_key;

        /* Check parameter */
        if (!oe_public_key_is_valid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        /* Release the key */
        BCryptDestroyKey(impl->pkey);

        /* Clear the fields of the implementation */
        oe_secure_zero_fill(impl, sizeof(*impl));
    }

    result = OE_OK;

done:
    return result;
}
