// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/rsa.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/utils.h>

#include "bcrypt.h"
#include "key.h"
#include "magic.h"
#include "rsa.h"

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_rsa_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_rsa_private_key_t));

/* Caller is responsible for calling BCryptDestroyKey on key_handle */
static oe_result_t _bcrypt_decode_rsa_private_key(
    const BYTE* der_data,
    DWORD der_data_size,
    BCRYPT_KEY_HANDLE* key_handle)
{
    oe_result_t result = OE_UNEXPECTED;
    BYTE* key_blob = NULL;
    DWORD key_blob_size = 0;

    BOOL success = CryptDecodeObjectEx(
        X509_ASN_ENCODING,
        CNG_RSA_PRIVATE_KEY_BLOB,
        der_data,
        der_data_size,
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        NULL,
        &key_blob,
        &key_blob_size);

    if (!success)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CryptDecodeObjectEx failed (err=%#x)\n",
            GetLastError());

    NTSTATUS status = BCryptImportKeyPair(
        BCRYPT_RSA_ALG_HANDLE,
        NULL,
        BCRYPT_RSAPRIVATE_BLOB,
        key_handle,
        key_blob,
        key_blob_size,
        0);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptImportKeyPair failed (err=%#x)\n", status);

    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        LocalFree(key_blob);
        key_blob_size = 0;
    }

    return result;
}

/* Caller is responsible for calling LocalFree on der_data  */
static oe_result_t _bcrypt_encode_rsa_public_key(
    const BCRYPT_KEY_HANDLE key_handle,
    BYTE** der_data,
    DWORD* der_data_size)
{
    return oe_bcrypt_encode_x509_public_key(
        key_handle, szOID_RSA_RSA, der_data, der_data_size);
}

/* Caller is responsible for calling LocalFree on der_data  */
static oe_result_t _bcrypt_encode_rsa_private_key(
    const BCRYPT_KEY_HANDLE key_handle,
    BYTE** der_data,
    DWORD* der_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    BYTE* key_blob = NULL;
    DWORD key_blob_size = 0;

    OE_CHECK(oe_bcrypt_export_key(
        key_handle, BCRYPT_RSAFULLPRIVATE_BLOB, &key_blob, &key_blob_size));

    {
        /* Encode the key_info structure as a X509 public key */
        BOOL success = CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            CNG_RSA_PRIVATE_KEY_BLOB,
            key_blob,
            CRYPT_ENCODE_ALLOC_FLAG,
            NULL,
            der_data,
            der_data_size);

        if (!success)
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CryptEncodeObjectEx failed (err=%#x)\n",
                GetLastError());
    }

    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        free(key_blob);
        key_blob_size = 0;
    }

    return result;
}

/* Caller is responsible for calling free on padding_info->config */
static oe_result_t _get_padding_info(
    oe_hash_type_t hash_type,
    size_t hash_size,
    oe_bcrypt_padding_info_t* padding_info)
{
    oe_result_t result = OE_UNEXPECTED;
    PCWSTR hash_algorithm = NULL;

    /* Check for support hash types and correct sizes. */
    switch (hash_type)
    {
        case OE_HASH_TYPE_SHA256:
            if (hash_size != 32)
                OE_RAISE(OE_INVALID_PARAMETER);
            hash_algorithm = BCRYPT_SHA256_ALGORITHM;
            break;
        case OE_HASH_TYPE_SHA512:
            if (hash_size != 64)
                OE_RAISE(OE_INVALID_PARAMETER);
            hash_algorithm = BCRYPT_SHA512_ALGORITHM;
            break;
        default:
            OE_RAISE(OE_INVALID_PARAMETER);
    }

    /*
     * Note that we use the less secure PKCS1 signature padding
     * because Intel requires it for SGX enclave signatures.
     */
    padding_info->type = BCRYPT_PAD_PKCS1;
    padding_info->config = malloc(sizeof(BCRYPT_PKCS1_PADDING_INFO));
    if (!padding_info->config)
        OE_RAISE(OE_OUT_OF_MEMORY);

    BCRYPT_PKCS1_PADDING_INFO* info =
        (BCRYPT_PKCS1_PADDING_INFO*)(padding_info->config);
    info->pszAlgId = hash_algorithm;

    result = OE_OK;

done:
    return result;
}

void oe_rsa_public_key_init(
    oe_rsa_public_key_t* public_key,
    BCRYPT_KEY_HANDLE* key_handle)
{
    oe_bcrypt_key_init(
        (oe_bcrypt_key_t*)public_key, key_handle, OE_RSA_PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_from_engine(
    oe_rsa_private_key_t* private_key,
    const char* engine_id,
    const char* engine_load_path,
    const char* key_id)
{
    /*
     * bcrypt does not support engines, so nothing to do.
     */
    return OE_UNSUPPORTED;
}

oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_data_size)
{
    return oe_bcrypt_key_read_pem(
        pem_data,
        pem_data_size,
        OE_RSA_PRIVATE_KEY_MAGIC,
        _bcrypt_decode_rsa_private_key,
        (oe_bcrypt_key_t*)private_key);
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_private_key_write_pem(
    const oe_rsa_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_data_size)
{
    return oe_bcrypt_key_write_pem(
        (const oe_bcrypt_key_t*)private_key,
        OE_RSA_PRIVATE_KEY_MAGIC,
        _bcrypt_encode_rsa_private_key,
        pem_data,
        pem_data_size);
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_read_pem(
    oe_rsa_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_data_size)
{
    return oe_bcrypt_key_read_pem(
        pem_data,
        pem_data_size,
        OE_RSA_PUBLIC_KEY_MAGIC,
        oe_bcrypt_decode_x509_public_key,
        (oe_bcrypt_key_t*)public_key);
}

/* Used by tests/crypto/rsa_tests
 * Also used by common/cert.c for tlsverifier.c now */
oe_result_t oe_rsa_public_key_write_pem(
    const oe_rsa_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_data_size)
{
    return oe_bcrypt_key_write_pem(
        (const oe_bcrypt_key_t*)public_key,
        OE_RSA_PUBLIC_KEY_MAGIC,
        _bcrypt_encode_rsa_public_key,
        pem_data,
        pem_data_size);
}

oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* private_key)
{
    return oe_bcrypt_key_free(
        (oe_bcrypt_key_t*)private_key, OE_RSA_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* public_key)
{
    return oe_bcrypt_key_free(
        (oe_bcrypt_key_t*)public_key, OE_RSA_PUBLIC_KEY_MAGIC);
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
    oe_bcrypt_padding_info_t padding_info = {0};
    OE_CHECK(_get_padding_info(hash_type, hash_size, &padding_info));
    OE_CHECK(oe_private_key_sign(
        (oe_private_key_t*)private_key,
        OE_RSA_PRIVATE_KEY_MAGIC,
        &padding_info,
        hash_data,
        hash_size,
        signature,
        signature_size));

    result = OE_OK;

done:
    if (padding_info.config)
        free(padding_info.config);

    return result;
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_verify(
    const oe_rsa_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_bcrypt_padding_info_t padding_info = {0};
    OE_CHECK(_get_padding_info(hash_type, hash_size, &padding_info));
    OE_CHECK(oe_public_key_verify(
        (oe_public_key_t*)public_key,
        OE_RSA_PUBLIC_KEY_MAGIC,
        &padding_info,
        hash_data,
        hash_size,
        signature,
        signature_size));

    result = OE_OK;

done:
    if (padding_info.config)
        free(padding_info.config);

    return result;
}

oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* public_key,
    uint8_t* modulus,
    size_t* modulus_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    BYTE* key_blob = NULL;
    ULONG key_blob_size = 0;
    BCRYPT_RSAKEY_BLOB* keyblob = NULL;

    /* Check for null parameters and invalid sizes. */
    if (!oe_bcrypt_key_is_valid(impl, OE_RSA_PUBLIC_KEY_MAGIC) ||
        !modulus_size || *modulus_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If modulus is null, then modulus_size must be zero */
    if (!modulus && *modulus_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_export_key(
        impl->handle, BCRYPT_RSAPUBLIC_BLOB, &key_blob, &key_blob_size));

    keyblob = (BCRYPT_RSAKEY_BLOB*)key_blob;
    assert(keyblob->cbModulus != 0);
    if (keyblob->cbModulus > *modulus_size)
    {
        *modulus_size = keyblob->cbModulus;

        if (modulus)
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        /* If modulus is null, this call is intented to get the correct
         * modulus_size so no need to trace OE_BUFFER_TOO_SMALL */
        else
            OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * A RSA public key BCrypt blob has the following format in contiguous
     * memory:
     *   BCRYPT_RSAKEY_BLOB struct
     *   PublicExponent[cbPublicExp] in big endian
     *   Modulus[cbModulus] in big endian
     */
    OE_CHECK(oe_memcpy_s(
        modulus,
        *modulus_size,
        key_blob + sizeof(*keyblob) + keyblob->cbPublicExp,
        keyblob->cbModulus));

    *modulus_size = keyblob->cbModulus;
    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        free(key_blob);
        key_blob_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_public_key_get_exponent(
    const oe_rsa_public_key_t* public_key,
    uint8_t* exponent,
    size_t* exponent_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const oe_public_key_t* impl = (const oe_public_key_t*)public_key;
    BYTE* key_blob = NULL;
    ULONG key_blob_size = 0;
    BCRYPT_RSAKEY_BLOB* keyblob;

    /* Check for null parameters and invalid sizes. */
    if (!oe_bcrypt_key_is_valid(impl, OE_RSA_PUBLIC_KEY_MAGIC) ||
        !exponent_size || *exponent_size > MAXDWORD)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* If exponent is null, then exponent_size must be zero */
    if (!exponent && *exponent_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_export_key(
        impl->handle, BCRYPT_RSAPUBLIC_BLOB, &key_blob, &key_blob_size));

    keyblob = (BCRYPT_RSAKEY_BLOB*)key_blob;
    assert(keyblob->cbPublicExp != 0);
    if (keyblob->cbPublicExp > *exponent_size)
    {
        *exponent_size = keyblob->cbPublicExp;

        if (exponent)
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        /* If exponent is null, this call is intented to get the correct
         * exponent_size so no need to trace OE_BUFFER_TOO_SMALL */
        else
            OE_RAISE_NO_TRACE(OE_BUFFER_TOO_SMALL);
    }

    /*
     * A RSA public key BCrypt blob has the following format in contiguous
     * memory:
     *   BCRYPT_RSAKEY_BLOB struct
     *   PublicExponent[cbPublicExp] in big endian
     *   Modulus[cbModulus] in big endian
     */
    OE_CHECK(oe_memcpy_s(
        exponent,
        *exponent_size,
        key_blob + sizeof(*keyblob),
        keyblob->cbPublicExp));

    *exponent_size = keyblob->cbPublicExp;
    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        free(key_blob);
        key_blob_size = 0;
    }

    return result;
}

/* Used by tests/crypto/rsa_tests */
oe_result_t oe_rsa_public_key_equal(
    const oe_rsa_public_key_t* public_key1,
    const oe_rsa_public_key_t* public_key2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;

    /* key1 and key2 are both BCRYPT_RSAKEY_BLOB structures
     * which should be comparable as raw byte buffers.
     */
    BYTE* key1 = NULL;
    BYTE* key2 = NULL;
    ULONG key1_size = 0;
    ULONG key2_size = 0;

    if (equal)
        *equal = false;
    else
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_key_get_blob(
        (oe_bcrypt_key_t*)public_key1,
        OE_RSA_PUBLIC_KEY_MAGIC,
        BCRYPT_RSAPUBLIC_BLOB,
        &key1,
        &key1_size));

    OE_CHECK(oe_bcrypt_key_get_blob(
        (oe_bcrypt_key_t*)public_key2,
        OE_RSA_PUBLIC_KEY_MAGIC,
        BCRYPT_RSAPUBLIC_BLOB,
        &key2,
        &key2_size));

    if ((key1_size == key2_size) &&
        oe_constant_time_mem_equal(key1, key2, key1_size))
    {
        *equal = true;
    }

    result = OE_OK;

done:
    if (key1)
    {
        oe_secure_zero_fill(key1, key1_size);
        free(key1);
        key1_size = 0;
    }

    if (key2)
    {
        oe_secure_zero_fill(key2, key2_size);
        free(key2);
        key2_size = 0;
    }
    return result;
}

oe_result_t oe_rsa_get_public_key_from_private(
    const oe_rsa_private_key_t* private_key,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_private_key_t* impl = (oe_private_key_t*)private_key;
    BYTE* key_blob = NULL;
    ULONG key_blob_size = 0;

    if (public_key)
        memset(public_key, 0, sizeof(oe_rsa_public_key_t));

    if (!oe_bcrypt_key_is_valid(impl, OE_RSA_PRIVATE_KEY_MAGIC) || !public_key)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_export_key(
        impl->handle, BCRYPT_RSAPUBLIC_BLOB, &key_blob, &key_blob_size));
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
            key_blob,
            key_blob_size,
            0);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE(OE_CRYPTO_ERROR);

        oe_rsa_public_key_init(public_key, public_key_handle);
    }

    result = OE_OK;

done:
    if (key_blob)
    {
        oe_secure_zero_fill(key_blob, key_blob_size);
        free(key_blob);
        key_blob_size = 0;
    }

    return result;
}

oe_result_t oe_rsa_public_key_from_modulus(
    const uint8_t* modulus,
    size_t modulus_size,
    const uint8_t* exponent,
    size_t exponent_size,
    oe_rsa_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    NTSTATUS status;
    BCRYPT_KEY_HANDLE key_handle;
    uint8_t* key_data_bytes = NULL;
    size_t key_data_size = 0;

    if (!public_key || modulus_size > ULONG_MAX || exponent_size > ULONG_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    key_data_size = sizeof(BCRYPT_RSAKEY_BLOB) + exponent_size + modulus_size;
    key_data_bytes = malloc(key_data_size);
    if (!key_data_bytes)
        OE_RAISE(OE_OUT_OF_MEMORY);

    BCRYPT_RSAKEY_BLOB* blob = (BCRYPT_RSAKEY_BLOB*)key_data_bytes;

    blob->BitLength = (ULONG)modulus_size;
    blob->cbModulus = (ULONG)modulus_size;
    blob->cbPublicExp = (ULONG)exponent_size;
    blob->Magic = BCRYPT_RSAPUBLIC_MAGIC;
    blob->cbPrime1 = 0;
    blob->cbPrime2 = 0;

    OE_CHECK(oe_memcpy_s(
        key_data_bytes + sizeof(BCRYPT_RSAKEY_BLOB),
        (ULONG)exponent_size,
        exponent,
        (ULONG)exponent_size));
    OE_CHECK(oe_memcpy_s(
        key_data_bytes + sizeof(BCRYPT_RSAKEY_BLOB) + exponent_size,
        (ULONG)modulus_size,
        modulus,
        (ULONG)modulus_size));

    status = BCryptImportKeyPair(
        BCRYPT_RSA_ALG_HANDLE,
        NULL,
        BCRYPT_RSAPUBLIC_BLOB,
        &key_handle,
        (PUCHAR)key_data_bytes,
        (ULONG)key_data_size,
        BCRYPT_NO_KEY_VALIDATION);

    if (!BCRYPT_SUCCESS(status))
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR, "BCryptImportKeyPair failed with %#x", status);

    oe_rsa_public_key_init(public_key, key_handle);

    result = OE_OK;

done:
    free(key_data_bytes);

    return result;
}
