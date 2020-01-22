// Copyright (c) Open Enclave SDK contributors.
// Licensed under the MIT License.

#include <assert.h>
#include <openenclave/internal/safecrt.h>
#include <openenclave/internal/ec.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>

#include "../magic.h"
#include "bcrypt.h"
#include "ec.h"
#include "key.h"
#include "pem.h"

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_ec_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_ec_private_key_t));

static const DWORD OE_BCRYPT_UNSUPPORTED_EC_TYPE = 0;
static const BYTE OE_X509_KEY_TYPE_UNCOMPRESSED = 0x04;

static DWORD _get_bcrypt_magic(oe_ec_type_t ec_type)
{
    switch (ec_type)
    {
        /* Note that bcrypt magic is more specific than OpenSSL NID:
         * - Distinguishes between ECDSA/ECDH keys
         * - Distinguishes between public/private keys
         */
        case OE_EC_TYPE_SECP256R1:
            return BCRYPT_ECDSA_PUBLIC_P256_MAGIC;
        default:
            return OE_BCRYPT_UNSUPPORTED_EC_TYPE;
    }
}

/* This method will dispose of an existing key_info if it allocates a
 * modified version. In any case, the caller is expected to call free
 * on the referenced key_info. */
static oe_result_t _fixup_public_key_info_for_import(
    PCERT_PUBLIC_KEY_INFO* key_info_ref,
    DWORD* key_info_size)
{
    oe_result_t result = OE_UNEXPECTED;
    PCERT_PUBLIC_KEY_INFO key_info = *key_info_ref;
    BYTE* new_key_info_buffer = NULL;
    DWORD new_key_info_buffer_size = 0;

    /* NOTE: As with the rest of ec.c, this implementation currrently only
     * deals with the SECP256 curve for EC */
    const uint32_t ECDSA_P256_PRIVATE_KEY_SIZE = 32;

    /* If the public key encoding is shorter than would be expected for
     * a P256 public key with a leading compressing type byte, it suggests
     * that the encoding has stripped leading zero bytes and this method
     * will rewrite the key_info to put them back in. */
    const uint32_t ECDSA_P256_PUBLIC_KEY_IMPORT_SIZE =
        (2 * ECDSA_P256_PRIVATE_KEY_SIZE + 1);

    if (key_info->PublicKey.cbData < ECDSA_P256_PUBLIC_KEY_IMPORT_SIZE)
    {
        PCERT_PUBLIC_KEY_INFO new_key_info = NULL;
        BYTE* key_info_base = (BYTE*)key_info;

        /* Assert that the public has even size after removing the tag
         * byte indication compression type. There's no way to tell whether
         * x or y requires leading zeros if they don't both require it. */
        assert((key_info->PublicKey.cbData - 1) % 2 == 0);

        DWORD xy_size = (key_info->PublicKey.cbData - 1) / 2;
        new_key_info_buffer_size =
            *key_info_size +
            (ECDSA_P256_PUBLIC_KEY_IMPORT_SIZE - key_info->PublicKey.cbData);

        /* Only handle uncompressed public key representations */
        if (key_info->PublicKey.pbData[0] != OE_X509_KEY_TYPE_UNCOMPRESSED)
            OE_RAISE_MSG(
                OE_UNSUPPORTED,
                "_fixup_public_key_info_for_import does not support compressed "
                "public key type: %x\n",
                key_info->PublicKey.pbData[0]);

        /* Clone the existing key_info */
        new_key_info_buffer = (BYTE*)malloc(new_key_info_buffer_size);
        if (!new_key_info_buffer)
            OE_RAISE(OE_OUT_OF_MEMORY);

        memcpy_s(
            new_key_info_buffer,
            new_key_info_buffer_size,
            key_info,
            *key_info_size);

        /* CERT_PUBLIC_KEY_INFO data fields are contiguous with the end of
         * struct, fixup the pointers in the new struct based on the relative
         * offsets from the original */
        new_key_info = (PCERT_PUBLIC_KEY_INFO)new_key_info_buffer;
        new_key_info->Algorithm.pszObjId =
            (PSTR)new_key_info_buffer +
            (key_info->Algorithm.pszObjId - (PSTR)key_info_base);
        new_key_info->Algorithm.Parameters.pbData =
            new_key_info_buffer +
            (key_info->Algorithm.Parameters.pbData - key_info_base);
        new_key_info->PublicKey.pbData =
            new_key_info_buffer + (key_info->PublicKey.pbData - key_info_base);
        new_key_info->PublicKey.cbData = ECDSA_P256_PUBLIC_KEY_IMPORT_SIZE;

        assert(
            new_key_info->PublicKey.pbData + new_key_info->PublicKey.cbData <=
            new_key_info_buffer + new_key_info_buffer_size);

        /* Zero the new public key data buffer */
        oe_secure_zero_fill(
            new_key_info->PublicKey.pbData, new_key_info->PublicKey.cbData);

        /* Set the tag for uncompressed public key */
        new_key_info->PublicKey.pbData[0] = OE_X509_KEY_TYPE_UNCOMPRESSED;

        /* Copy the x coordinate of the public key*/
        memcpy_s(
            new_key_info->PublicKey.pbData + 1,
            xy_size,
            key_info->PublicKey.pbData + 1,
            xy_size);

        /* Copy the y coordinate of the public key*/
        memcpy_s(
            new_key_info->PublicKey.pbData + 1 + ECDSA_P256_PRIVATE_KEY_SIZE,
            xy_size,
            key_info->PublicKey.pbData + 1 + xy_size,
            xy_size);

        /* Clear the old key_info and assign the fixed up version */
        oe_secure_zero_fill(key_info, *key_info_size);
        *key_info_ref = new_key_info;
        *key_info_size = new_key_info_buffer_size;
        new_key_info_buffer = NULL;
    }

    result = OE_OK;

done:
    if (new_key_info_buffer)
    {
        oe_secure_zero_fill(new_key_info_buffer, new_key_info_buffer_size);
        free(new_key_info_buffer);
        new_key_info_buffer_size = 0;
    }

    return result;
}

/* Caller is responsible for calling BCryptDestroyKey on private_key */
static oe_result_t _bcrypt_import_ec_private_key(
    ULONG ec_key_magic,
    const BYTE* d_data,
    DWORD d_data_size,
    BCRYPT_KEY_HANDLE* private_key)
{
    OE_UNUSED(ec_key_magic);

    oe_result_t result = OE_UNEXPECTED;
    DWORD key_blob_size = 0;
    BYTE* key_blob = NULL;

    /* Construct a BCRYPT_ECCPRIVATE_BLOB for BCryptImportKeyPair.
     *
     * See documentation of BCRYPT_ECCKEY_BLOB at:
     https://docs.microsoft.com/en-us/windows/desktop/api/bcrypt/ns-bcrypt-_bcrypt_ecckey_blob
     *
     *    struct BCRYPT_ECCPRIVATE_BLOB
     *    {
     *       struct BCRYPT_ECCKEY_BLOB
     *       {
     *           ULONG dwMagic;
     *           ULONG cbKey;
     *       };
     *       BYTE X[cbKey]; // Big-endian
     *       BYTE Y[cbKey]; // Big-endian
     *       BYTE d[cbKey]; // Big-endian
     *    }
     */

    key_blob_size = sizeof(BCRYPT_ECCKEY_BLOB) + (3 * d_data_size);
    key_blob = (BYTE*)malloc(key_blob_size);
    if (!key_blob)
        OE_RAISE(OE_OUT_OF_MEMORY);

    {
        PBCRYPT_ECCKEY_BLOB key_header = (PBCRYPT_ECCKEY_BLOB)key_blob;
        key_header->dwMagic = BCRYPT_ECDSA_PRIVATE_P256_MAGIC;
        key_header->cbKey = d_data_size;

        /* BCrypt will recompute the public X & Y coordinates from the private
         * key d when imported if the fields are zeroed out. */
        BYTE* public_key = key_blob + sizeof(BCRYPT_ECCKEY_BLOB);
        DWORD public_key_size = 2 * key_header->cbKey;
        oe_secure_zero_fill(public_key, public_key_size);

        /* Copy the private key into offset for d in BCRYPT_ECCPRIVATE_BLOB */
        BYTE* d = key_blob + sizeof(BCRYPT_ECCKEY_BLOB) + public_key_size;
        OE_CHECK(oe_memcpy_s(d, d_data_size, d_data, d_data_size));
    }

    {
        /* Import the private key into a BCRYPT_KEY_HANDLE */
        NTSTATUS status = BCryptImportKeyPair(
            BCRYPT_ECDSA_P256_ALG_HANDLE,
            NULL,
            BCRYPT_ECCPRIVATE_BLOB,
            private_key,
            key_blob,
            key_blob_size,
            0);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "BCryptImportKeyPair failed (err=%#x)\n",
                status);
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

/* Caller is responsible for calling BCryptDestroyKey on key_handle */
static oe_result_t _bcrypt_export_ec_public_key_from_private(
    const BCRYPT_KEY_HANDLE private_key,
    BCRYPT_KEY_HANDLE* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    PCERT_PUBLIC_KEY_INFO key_info = NULL;
    DWORD key_info_size = 0;

    OE_CHECK(oe_bcrypt_get_public_key_info(
        private_key, szOID_ECC_CURVE_P256, &key_info, &key_info_size));

    /* NOTE: This additional step is necessary because it is possible for
     * CryptExportPublicKeyInfoFromBCryptKeyHandle to return a public key
     * where the EC x & y coordinates have their leading zeros stripped,
     * but CryptImportPublicKeyInfoEx2 rejects public key encodings that
     * do not have them. This step checks for this condition and rewrites
     * the key_info into the expected format. */
    OE_CHECK(_fixup_public_key_info_for_import(&key_info, &key_info_size));

    {
        /* Import the public key info into a BCRYPT_KEY_HANDLE */
        BOOL success = CryptImportPublicKeyInfoEx2(
            X509_ASN_ENCODING, key_info, 0, NULL, public_key);

        if (!success)
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CryptImportPublicKeyInfoEx2 failed "
                "(err=%#x)\n",
                GetLastError());
    }

    result = OE_OK;

done:
    if (key_info)
    {
        oe_secure_zero_fill(key_info, key_info_size);
        free(key_info);
        key_info_size = 0;
    }

    return result;
}

/* Caller is responsible for calling BCryptDestroyKey on key_handle */
static oe_result_t _bcrypt_decode_ec_private_key(
    const BYTE* der_data,
    DWORD der_data_size,
    BCRYPT_KEY_HANDLE* key_handle)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* key_info_data = NULL;
    DWORD key_info_data_size = 0;
    PCRYPT_ECC_PRIVATE_KEY_INFO key_info = NULL;

    /* Decode the PEM into CRYPT_ECC_PRIVATE_KEY_INFO struct */
    BOOL success = CryptDecodeObjectEx(
        X509_ASN_ENCODING,
        X509_ECC_PRIVATE_KEY,
        der_data,
        der_data_size,
        CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
        NULL,
        &key_info_data,
        &key_info_data_size);

    if (!success)
        OE_RAISE_MSG(
            OE_CRYPTO_ERROR,
            "CryptDecodeObjectEx failed (err=%#x)\n",
            GetLastError());

    key_info = (PCRYPT_ECC_PRIVATE_KEY_INFO)key_info_data;

    /* We want to import the CRYPT_ECC_PRIVATE_KEY_INFO into a
     * BCRYPT_KEY_HANDLE for use, but BCrypt doesn't offer any methods
     * to do this directly.
     *
     * While we could CryptDecodeObjectEx on key_info.PublicKey to extract
     * the ASN-decoded X & Y values from the CRYPT_BIT_BLOB, it's not
     * neeeded as BCrypt will recompute them from the private key on import.
     *
     * Note: When oe_ec_private_key_read_pem supports more than P256 curve,
     * The ec_key_magic should be derived from key_info->szCurveOid.
     */
    OE_CHECK(_bcrypt_import_ec_private_key(
        BCRYPT_ECDSA_PRIVATE_P256_MAGIC,
        key_info->PrivateKey.pbData,
        key_info->PrivateKey.cbData,
        key_handle));

    result = OE_OK;

done:
    if (key_info_data)
    {
        oe_secure_zero_fill(key_info_data, key_info_data_size);
        LocalFree(key_info_data);
        key_info_data_size = 0;
    }

    return result;
}

/* Caller is responsible for calling LocalFree on der_data  */
static oe_result_t _bcrypt_encode_ec_private_key(
    const BCRYPT_KEY_HANDLE key_handle,
    BYTE** der_data,
    DWORD* der_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    BYTE* key_blob = NULL;
    DWORD key_blob_size = 0;
    CRYPT_BIT_BLOB public_key_bits = {0};
    BCRYPT_ECCKEY_BLOB* key_header = NULL;

    OE_CHECK(oe_bcrypt_export_key(
        key_handle, BCRYPT_ECCPRIVATE_BLOB, &key_blob, &key_blob_size));

    key_header = (BCRYPT_ECCKEY_BLOB*)key_blob;

    /* Per RFC5480, ECPoint public key is the X & Y coordinate plus a first
     * octect indicating whether the key is compressed or uncommpressed. */
    public_key_bits.cbData = 1 + (key_header->cbKey * 2);
    public_key_bits.pbData = (BYTE*)malloc(public_key_bits.cbData);
    if (!public_key_bits.pbData)
        OE_RAISE(OE_OUT_OF_MEMORY);

    public_key_bits.pbData[0] = OE_X509_KEY_TYPE_UNCOMPRESSED;
    OE_CHECK(oe_memcpy_s(
        public_key_bits.pbData + 1,
        public_key_bits.cbData - 1,
        key_blob + sizeof(BCRYPT_ECCKEY_BLOB),
        key_header->cbKey * 2));

    {
        CRYPT_ECC_PRIVATE_KEY_INFO key_info = {0};
        key_info.dwVersion = CRYPT_ECC_PRIVATE_KEY_INFO_v1;
        key_info.szCurveOid = szOID_ECC_CURVE_P256;
        key_info.PrivateKey.cbData = key_header->cbKey;
        key_info.PrivateKey.pbData =
            key_blob + sizeof(BCRYPT_ECCKEY_BLOB) + 2 * key_header->cbKey;
        key_info.PublicKey = public_key_bits;

        BOOL success = CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_ECC_PRIVATE_KEY,
            &key_info,
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
    if (public_key_bits.pbData)
        free(public_key_bits.pbData);

    if (key_blob)
        free(key_blob);

    return result;
}

/* Caller is responsible for calling LocalFree on der_data  */
static oe_result_t _bcrypt_encode_ec_public_key(
    const BCRYPT_KEY_HANDLE key_handle,
    BYTE** der_data,
    DWORD* der_data_size)
{
    return oe_bcrypt_encode_x509_public_key(
        key_handle, szOID_ECC_PUBLIC_KEY, der_data, der_data_size);
}

static inline oe_result_t _reverse_endian(
    bool is_dest_big_endian,
    uint8_t* dest,
    uint32_t dest_size,
    const uint8_t* src,
    uint32_t src_size)
{
    oe_result_t result = OE_UNEXPECTED;
    const uint8_t* end = src + src_size;

    if (src_size > dest_size)
        OE_RAISE(OE_BUFFER_TOO_SMALL);

    /* If big endian, add leading zeros first */
    if (is_dest_big_endian && dest_size > src_size)
    {
        for (uint32_t i = 0; i < dest_size - src_size; i++)
            *dest++ = 0;
    }

    for (uint32_t copy_size = src_size; copy_size > 0; copy_size--)
        *dest++ = *--end;

    /* If little endian, add leading zeros at the end */
    if (!is_dest_big_endian && dest_size > src_size)
    {
        for (uint32_t i = 0; i < dest_size - src_size; i++)
            *dest++ = 0;
    }

    result = OE_OK;

done:
    return result;
}

void oe_ec_public_key_init(
    oe_ec_public_key_t* public_key,
    BCRYPT_KEY_HANDLE* key_handle)
{
    oe_bcrypt_key_init(
        (oe_bcrypt_key_t*)public_key, key_handle, OE_EC_PUBLIC_KEY_MAGIC);
}

void oe_ec_private_key_init(
    oe_ec_private_key_t* private_key,
    BCRYPT_KEY_HANDLE* key_handle)
{
    oe_bcrypt_key_init(
        (oe_bcrypt_key_t*)private_key, key_handle, OE_EC_PRIVATE_KEY_MAGIC);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_private_key_read_pem(
    oe_ec_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_data_size)
{
    return oe_bcrypt_key_read_pem(
        pem_data,
        pem_data_size,
        OE_EC_PRIVATE_KEY_MAGIC,
        _bcrypt_decode_ec_private_key,
        (oe_bcrypt_key_t*)private_key);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_private_key_write_pem(
    const oe_ec_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_data_size)
{
    return oe_bcrypt_key_write_pem(
        (const oe_bcrypt_key_t*)private_key,
        OE_EC_PRIVATE_KEY_MAGIC,
        _bcrypt_encode_ec_private_key,
        pem_data,
        pem_data_size);
}

oe_result_t oe_ec_public_key_read_pem(
    oe_ec_public_key_t* public_key,
    const uint8_t* pem_data,
    size_t pem_data_size)
{
    return oe_bcrypt_key_read_pem(
        pem_data,
        pem_data_size,
        OE_EC_PUBLIC_KEY_MAGIC,
        oe_bcrypt_decode_x509_public_key,
        (oe_bcrypt_key_t*)public_key);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_public_key_write_pem(
    const oe_ec_public_key_t* public_key,
    uint8_t* pem_data,
    size_t* pem_data_size)
{
    return oe_bcrypt_key_write_pem(
        (const oe_bcrypt_key_t*)public_key,
        OE_EC_PUBLIC_KEY_MAGIC,
        _bcrypt_encode_ec_public_key,
        pem_data,
        pem_data_size);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_private_key_free(oe_ec_private_key_t* private_key)
{
    return oe_bcrypt_key_free(
        (oe_bcrypt_key_t*)private_key, OE_EC_PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_free(oe_ec_public_key_t* public_key)
{
    return oe_bcrypt_key_free(
        (oe_bcrypt_key_t*)public_key, OE_EC_PUBLIC_KEY_MAGIC);
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_private_key_sign(
    const oe_ec_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size)
{
    OE_UNUSED(hash_type);

    oe_result_t result = OE_UNEXPECTED;
    uint8_t* raw_signature = NULL;
    size_t raw_signature_size = 0;
    size_t max_encoded_size = 0;

    {
        oe_result_t size_result = oe_private_key_sign(
            (oe_private_key_t*)private_key,
            OE_EC_PRIVATE_KEY_MAGIC,
            NULL,
            hash_data,
            hash_size,
            NULL,
            &raw_signature_size);

        if (size_result == OE_BUFFER_TOO_SMALL)
        {
            raw_signature = (uint8_t*)malloc(raw_signature_size);
            if (!raw_signature)
                OE_RAISE(OE_OUT_OF_MEMORY);
            size_result = OE_OK;
        }
        OE_CHECK(size_result);
    }

    /* ECDSA signatures are randomized, which may lead to different encoding
     * sizes on subsequent calls. To avoid this, this method always returns
     * the upper limit of the encoding size.
     *
     * BCrypt produces a binary blob signature of the form: { r, s },
     * where r & s are the same length as the EC key which are stable
     * across different invocations of signing.
     *
     * The size of the DER encoding is then at most:
     *
     * TAG[1] + LEN[2] for SEQUENCE < 256 total bytes (SECP256 keys are 32)
     * + TAG[1] + LEN[1] + (Leading 0x0)[1] + [r_size] for INTEGER of r
     * + TAG[1] + LEN[1] + (Leading 0x0)[1] + [s_size] for INTEGER of s
     */
    max_encoded_size = 9 + raw_signature_size;
    if (!signature)
    {
        *signature_size = max_encoded_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    OE_CHECK(oe_private_key_sign(
        (oe_private_key_t*)private_key,
        OE_EC_PRIVATE_KEY_MAGIC,
        NULL,
        hash_data,
        hash_size,
        raw_signature,
        &raw_signature_size));

    {
        /* Encode the BCrypt binary signature blob into X509_ECC_SIGNATURE DER
         * format to be compatible with OpenSSL ECDSA output. */
        assert(raw_signature_size % 2 == 0);

        size_t r_size = raw_signature_size / 2;
        size_t s_size = r_size;
        uint8_t* r = raw_signature;
        uint8_t* s = raw_signature + r_size;

        {
            oe_result_t encode_result = oe_ecdsa_signature_write_der(
                signature, signature_size, r, r_size, s, s_size);
            if (encode_result == OE_BUFFER_TOO_SMALL)
            {
                assert(*signature_size <= max_encoded_size);
                *signature_size = max_encoded_size;
            }
            OE_CHECK(encode_result);
        }
    }

    result = OE_OK;

done:
    if (raw_signature)
        free(raw_signature);

    return result;
}

oe_result_t oe_ec_public_key_verify(
    const oe_ec_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size)
{
    OE_UNUSED(hash_type);

    oe_result_t result = OE_UNEXPECTED;
    BYTE* x509_signature = NULL;
    DWORD x509_signature_size = 0;
    BYTE* bcrypt_signature = NULL;
    DWORD bcrypt_signature_size = 0;
    DWORD key_length_bytes = 0;

    /* Check parameters, hash & key are checked in oe_public_key_verify */
    if (!signature || !signature_size || signature_size > MAXDWORD)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        BOOL success = CryptDecodeObjectEx(
            X509_ASN_ENCODING,
            X509_ECC_SIGNATURE,
            signature,
            (DWORD)signature_size,
            CRYPT_DECODE_ALLOC_FLAG | CRYPT_DECODE_NOCOPY_FLAG,
            NULL,
            &x509_signature,
            &x509_signature_size);

        if (!success)
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "CryptDecodeObjectEx failed (err=%#x)\n",
                GetLastError());
    }
    {
        DWORD key_length_bits = 0;
        DWORD bytes_written = 0;
        NTSTATUS status = BCryptGetProperty(
            ((oe_bcrypt_key_t*)public_key)->handle,
            BCRYPT_KEY_LENGTH,
            (PUCHAR)&key_length_bits,
            sizeof(key_length_bits),
            &bytes_written,
            0);

        if (!BCRYPT_SUCCESS(status))
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "BCryptGetProperty for BCRYPT_KEY_LENGTH failed (err=%#x)\n",
                GetLastError());

        key_length_bytes = key_length_bits / 8;
    }
    {
        /* CERT_ECC_SIGNATURE r & s values are little-endian, and have leading
         * zeroes stripped. BCryptVerifySignature expects a single contiguous
         * buffer of big-endian r & s values concatenated, with leading zeroes
         * so that r & s each have the same constant size as the signing key. */
        CERT_ECC_SIGNATURE* ecc_signature = (CERT_ECC_SIGNATURE*)x509_signature;
        if (key_length_bytes < ecc_signature->r.cbData ||
            key_length_bytes < ecc_signature->s.cbData)
            OE_RAISE_MSG(
                OE_INVALID_PARAMETER,
                "public_key has incorrect length for signature\n",
                NULL);

        bcrypt_signature_size = 2 * key_length_bytes;
        bcrypt_signature = (BYTE*)malloc(bcrypt_signature_size);
        if (!bcrypt_signature)
            OE_RAISE(OE_OUT_OF_MEMORY);

        OE_CHECK(_reverse_endian(
            true, /* To big-endian */
            bcrypt_signature,
            key_length_bytes,
            ecc_signature->r.pbData,
            ecc_signature->r.cbData));

        OE_CHECK(_reverse_endian(
            true, /* To big-endian */
            bcrypt_signature + key_length_bytes,
            key_length_bytes,
            ecc_signature->s.pbData,
            ecc_signature->s.cbData));
    }

    OE_CHECK(oe_public_key_verify(
        (oe_public_key_t*)public_key,
        OE_EC_PUBLIC_KEY_MAGIC,
        NULL,
        hash_data,
        hash_size,
        bcrypt_signature,
        bcrypt_signature_size));

    result = OE_OK;

done:
    if (bcrypt_signature)
        free(bcrypt_signature);

    if (x509_signature)
        LocalFree(x509_signature);

    return result;
}

/* Used by tests/crypto/ec_tests */
oe_result_t oe_ec_generate_key_pair_from_private(
    oe_ec_type_t ec_type,
    const uint8_t* d_data,
    size_t d_data_size,
    oe_ec_private_key_t* private_key,
    oe_ec_public_key_t* public_key)
{
    oe_result_t result = OE_UNEXPECTED;
    BCRYPT_KEY_HANDLE private_key_handle = NULL;
    BCRYPT_KEY_HANDLE public_key_handle = NULL;

    if (private_key)
        oe_secure_zero_fill(private_key, sizeof(oe_ec_private_key_t));

    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    if (!d_data || !private_key || !public_key || d_data_size > OE_INT_MAX)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    {
        DWORD ec_key_magic = _get_bcrypt_magic(ec_type);
        if (ec_key_magic == OE_BCRYPT_UNSUPPORTED_EC_TYPE)
            OE_RAISE_MSG(
                OE_UNSUPPORTED,
                "oe_ec_generate_key_pair_from_private does not support "
                "ec_type=%#x\n",
                ec_type);

        /* Import the private key */
        OE_CHECK(_bcrypt_import_ec_private_key(
            ec_key_magic, d_data, (DWORD)d_data_size, &private_key_handle));
    }

    /* Export the public key from the private key */
    OE_CHECK(_bcrypt_export_ec_public_key_from_private(
        private_key_handle, &public_key_handle));

    oe_ec_public_key_init(public_key, public_key_handle);
    public_key_handle = NULL;

    oe_ec_private_key_init(private_key, private_key_handle);
    private_key_handle = NULL;

    result = OE_OK;

done:
    if (public_key_handle)
        BCryptDestroyKey(public_key_handle);

    if (private_key_handle)
        BCryptDestroyKey(private_key_handle);

    return result;
}

oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* public_key1,
    const oe_ec_public_key_t* public_key2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;

    /* ec1 and ec2 are both BCRYPT_ECCKEY_BLOB structures
     * which should be comparable as raw byte buffers.
     */
    BYTE* ec1 = NULL;
    BYTE* ec2 = NULL;
    ULONG ec1_size = 0;
    ULONG ec2_size = 0;

    if (equal)
        *equal = false;
    else
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(oe_bcrypt_key_get_blob(
        (oe_bcrypt_key_t*)public_key1,
        OE_EC_PUBLIC_KEY_MAGIC,
        BCRYPT_ECCPUBLIC_BLOB,
        &ec1,
        &ec1_size));

    OE_CHECK(oe_bcrypt_key_get_blob(
        (oe_bcrypt_key_t*)public_key2,
        OE_EC_PUBLIC_KEY_MAGIC,
        BCRYPT_ECCPUBLIC_BLOB,
        &ec2,
        &ec2_size));

    /* All fields must match between the two EC keys to be equal.
     * See oe_ec_public_key_from_coordinates comments for description of
     * BCRYPT_ECCPUBLIC_BLOB */
    if (ec1_size == ec2_size && oe_constant_time_mem_equal(ec1, ec2, ec1_size))
    {
        *equal = true;
    }

    result = OE_OK;

done:
    if (ec1)
    {
        oe_secure_zero_fill(ec1, ec1_size);
        free(ec1);
        ec1_size = 0;
    }

    if (ec2)
    {
        oe_secure_zero_fill(ec2, ec2_size);
        free(ec2);
        ec2_size = 0;
    }

    return result;
}

oe_result_t oe_ec_public_key_from_coordinates(
    oe_ec_public_key_t* public_key,
    oe_ec_type_t ec_type,
    const uint8_t* x_data,
    size_t x_size,
    const uint8_t* y_data,
    size_t y_size)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t ec_key_buffer_size = 0;
    uint8_t* ec_key_buffer = NULL;
    BCRYPT_KEY_HANDLE ec_key_handle = NULL;

    if (public_key)
        oe_secure_zero_fill(public_key, sizeof(oe_ec_public_key_t));

    /* Reject invalid parameters */
    if (!public_key || !x_data || !x_size || x_size > OE_INT_MAX || !y_data ||
        !y_size || y_size > OE_INT_MAX || x_size != y_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Construct a BCRYPT_ECCPUBLIC_BLOB from X & Y coordinates.
     *
     * See documentation of BCRYPT_ECCKEY_BLOB at:
     https://docs.microsoft.com/en-us/windows/desktop/api/bcrypt/ns-bcrypt-_bcrypt_ecckey_blob
     *
     *    struct BCRYPT_ECCPUBLIC_BLOB
     *    {
     *       struct BCRYPT_ECCKEY_BLOB
     *       {
     *           ULONG dwMagic;
     *           ULONG cbKey;
     *       };
     *       BYTE X[cbKey]; // Big-endian
     *       BYTE Y[cbKey]; // Big-endian
     *    }
     */
    {
        ec_key_buffer_size = sizeof(BCRYPT_ECCKEY_BLOB) + 2 * x_size;
        ec_key_buffer = (uint8_t*)malloc(ec_key_buffer_size);
        if (!ec_key_buffer)
            OE_RAISE(OE_OUT_OF_MEMORY);

        BCRYPT_ECCKEY_BLOB* ec_key_blob = (BCRYPT_ECCKEY_BLOB*)ec_key_buffer;
        DWORD ec_key_magic = _get_bcrypt_magic(ec_type);
        if (ec_key_magic == OE_BCRYPT_UNSUPPORTED_EC_TYPE)
            OE_RAISE_MSG(
                OE_UNSUPPORTED,
                "oe_ec_public_key_from_coordinates does not support "
                "ec_type=%#x\n",
                ec_type);
        ec_key_blob->dwMagic = ec_key_magic;
        ec_key_blob->cbKey = (ULONG)x_size;

        uint8_t* ec_key_x = ec_key_buffer + sizeof(BCRYPT_ECCKEY_BLOB);
        uint8_t* ec_key_y = ec_key_x + x_size;

        oe_memcpy_s(ec_key_x, x_size, x_data, x_size);
        oe_memcpy_s(ec_key_y, y_size, y_data, y_size);
    }

    /* Import the key blob to obtain the key handle */
    {
        NTSTATUS status = BCryptImportKeyPair(
            BCRYPT_ECDSA_P256_ALG_HANDLE,
            NULL,
            BCRYPT_ECCPUBLIC_BLOB,
            &ec_key_handle,
            ec_key_buffer,
            (DWORD)ec_key_buffer_size,
            0); /* No dwFlags */

        if (!BCRYPT_SUCCESS(status))
        {
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR,
                "BCryptImportKeyPair failed(err=%#x)\n",
                status);
        }

        /* wrap as oe_ec_public_key_t compatible type */
        oe_ec_public_key_init(public_key, ec_key_handle);
        ec_key_handle = NULL;
    }

    result = OE_OK;

done:
    if (ec_key_buffer)
    {
        oe_secure_zero_fill(ec_key_buffer, ec_key_buffer_size);
        free(ec_key_buffer);
        ec_key_buffer_size = 0;
    }

    if (ec_key_handle)
        BCryptDestroyKey(ec_key_handle);

    return result;
}

oe_result_t oe_ecdsa_signature_write_der(
    unsigned char* signature,
    size_t* signature_size,
    const uint8_t* r_data,
    size_t r_data_size,
    const uint8_t* s_data,
    size_t s_data_size)
{
    oe_result_t result = OE_UNEXPECTED;
    DWORD encoded_size = (DWORD)(*signature_size);
    DWORD max_rs_size = 0;
    BYTE* r = NULL;
    BYTE* s = NULL;

    /* Reject invalid parameters */
    if (!signature_size || *signature_size > MAXDWORD || !r_data ||
        !r_data_size || r_data_size > OE_INT_MAX || !s_data || !s_data_size ||
        s_data_size > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature is null, then signature_size must be zero */
    if (!signature && *signature_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert the r & s data into little-endian for CERT_ECC_SIGNATURE.
     * This representation must have leading zeroes prior to ASN encoding,
     * but this method is not given the signing crypto algorithm or key
     * length, so it heuristically infers if leading zeros are padded:
     *  - Padded r & s values should have max sizes equal to key lengths,
     *    which are multiples of 2.
     *  - Padded r & s values have equal length in CERT_ECC_SIGNATURE.
     */
    max_rs_size =
        (DWORD)(r_data_size > s_data_size ? r_data_size : s_data_size);
    max_rs_size = (max_rs_size % 2 > 0) ? max_rs_size + 1 : max_rs_size;

    r = (BYTE*)malloc(max_rs_size);
    if (!r)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(_reverse_endian(
        false, r, (uint32_t)max_rs_size, r_data, (uint32_t)r_data_size));

    s = (BYTE*)malloc(max_rs_size);
    if (!s)
        OE_RAISE(OE_OUT_OF_MEMORY);

    OE_CHECK(_reverse_endian(
        false, s, (uint32_t)max_rs_size, s_data, (uint32_t)s_data_size));

    /* Encode the ECDSA siganture */
    {
        CERT_ECC_SIGNATURE ecc_sig = {{(DWORD)max_rs_size, r},
                                      {(DWORD)max_rs_size, s}};
        BOOL success = CryptEncodeObjectEx(
            X509_ASN_ENCODING,
            X509_ECC_SIGNATURE,
            &ecc_sig,
            0,
            NULL,
            signature,
            &encoded_size);

        /* CryptEncodeObjectEx will not raise an error if signature was
         * NULL but oe_ecdsa_signature_write_der still needs to raise
         * OE_BUFFER_TOO_SMALL in that case. */
        if (encoded_size > *signature_size)
        {
            *signature_size = (size_t)encoded_size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        if (!success)
        {
            /* The buffer too small case should already be handled before */
            DWORD err = GetLastError();
            assert(err != ERROR_MORE_DATA);
            OE_RAISE_MSG(
                OE_CRYPTO_ERROR, "CryptEncodeObjectEx failed (err=%#x)\n", err);
        }
    }

    /* Set the size of the output buffer */
    *signature_size = (size_t)encoded_size;

    result = OE_OK;

done:
    if (r)
        free(r);

    if (s)
        free(s);

    return result;
}

/* Used by tests/crypto/ec_tests */
bool oe_ec_valid_raw_private_key(
    oe_ec_type_t ec_type,
    const uint8_t* key,
    size_t key_size)
{
    bool ret = false;
    oe_ec_private_key_t private_key = {0};
    oe_ec_public_key_t public_key = {0};

    /* BCrypt does not support exposing EC Curve primitives such as order,
     * and does not provide bignum functions to perform low-level comparisons.
     *
     * oe_ec_valid_raw_private_key is only used in the enclave implementation,
     * and this implementation is only for test-compatibility.
     *
     * It defeats the purpose of this function as a fast sieve for generating
     * random EC private keys and must be replaced if it has a production use.
     */
    oe_result_t result = oe_ec_generate_key_pair_from_private(
        ec_type, key, key_size, &private_key, &public_key);

    if (result == OE_OK)
    {
        oe_ec_private_key_free(&private_key);
        oe_ec_public_key_free(&public_key);
        ret = true;
    }

    return ret;
}
