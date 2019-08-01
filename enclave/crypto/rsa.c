// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "rsa.h"
#include <openenclave/bits/safecrt.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/utils.h>
#include "key.h"
#include "pem.h"
#include "random_internal.h"

static uint64_t _PRIVATE_KEY_MAGIC = 0xd48de5bae3994b41;
static uint64_t _PUBLIC_KEY_MAGIC = 0x713600af058c447a;

OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_rsa_private_key_t));
OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_rsa_public_key_t));

static oe_result_t _copy_key(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copy_private_fields)
{
    oe_result_t result = OE_UNEXPECTED;
    const mbedtls_pk_info_t* info = NULL;
    mbedtls_rsa_context* rsa = NULL;
    int rc = 0;

    if (dest)
        mbedtls_pk_init(dest);

    /* Check for invalid parameters */
    if (!dest || !src)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Lookup the RSA info */
    if (!(info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))
        OE_RAISE(OE_PUBLIC_KEY_NOT_FOUND);

    /* If not an RSA key */
    if (src->pk_info != info)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* Setup the context for this key type */
    rc = mbedtls_pk_setup(dest, info);
    if (rc != 0)
        OE_RAISE_MSG(OE_CRYPTO_ERROR, "rc = 0x%x\n", rc);

    /* Get the context for this key type */
    if (!(rsa = dest->pk_ctx))
        OE_RAISE(OE_FAILURE);

    /* Initialize the RSA key from the source */
    if (mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(*src)) != 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    /* If not a private key, then clear private key fields */
    if (!copy_private_fields)
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

    result = OE_OK;

done:

    if (result != OE_OK)
        mbedtls_pk_free(dest);

    return result;
}

static oe_result_t _get_public_key_modulus_or_exponent(
    const oe_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size,
    bool get_modulus)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t required_size;
    mbedtls_rsa_context* rsa;
    const mbedtls_mpi* mpi;

    /* Check for invalid parameters */
    if (!oe_public_key_is_valid(public_key, _PUBLIC_KEY_MAGIC) || !buffer_size)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then buffer_size must be zero */
    if (!buffer && *buffer_size != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the RSA context */
    if (!(rsa = public_key->pk.pk_ctx))
        OE_RAISE(OE_FAILURE);

    /* Pick modulus or exponent */
    if (!(mpi = get_modulus ? &rsa->N : &rsa->E))
        OE_RAISE(OE_FAILURE);

    /* Determine the required size in bytes */
    required_size = mbedtls_mpi_size(mpi);

    /* If buffer is null or not big enough */
    if (!buffer || (*buffer_size < required_size))
    {
        *buffer_size = required_size;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy key bytes to the caller's buffer */
    if (mbedtls_mpi_write_binary(mpi, buffer, required_size) != 0)
        OE_RAISE(OE_CRYPTO_ERROR);

    *buffer_size = required_size;

    result = OE_OK;

done:

    return result;
}

oe_result_t oe_public_key_get_modulus(
    const oe_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    return _get_public_key_modulus_or_exponent(
        public_key, buffer, buffer_size, true);
}

oe_result_t oe_public_key_get_exponent(
    const oe_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    return _get_public_key_modulus_or_exponent(
        public_key, buffer, buffer_size, false);
}

static oe_result_t oe_public_key_equal(
    const oe_public_key_t* public_key1,
    const oe_public_key_t* public_key2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!oe_public_key_is_valid(public_key1, _PUBLIC_KEY_MAGIC) ||
        !oe_public_key_is_valid(public_key2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Compare the exponent and modulus */
    {
        const mbedtls_rsa_context* rsa1 = public_key1->pk.pk_ctx;
        const mbedtls_rsa_context* rsa2 = public_key2->pk.pk_ctx;

        if (!rsa1 || !rsa2)
            OE_RAISE(OE_INVALID_PARAMETER);

        if (mbedtls_mpi_cmp_mpi(&rsa1->N, &rsa2->N) == 0 &&
            mbedtls_mpi_cmp_mpi(&rsa1->E, &rsa2->E) == 0)
        {
            *equal = true;
        }
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_rsa_public_key_init(
    oe_rsa_public_key_t* public_key,
    const mbedtls_pk_context* pk)
{
    return oe_public_key_init(
        (oe_public_key_t*)public_key, pk, _copy_key, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_private_key_read_pem(
        pem_data,
        pem_size,
        (oe_private_key_t*)private_key,
        MBEDTLS_PK_RSA,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_write_pem(
    const oe_rsa_private_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_private_key_write_pem(
        (const oe_private_key_t*)private_key,
        pem_data,
        pem_size,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_read_pem(
    oe_rsa_public_key_t* private_key,
    const uint8_t* pem_data,
    size_t pem_size)
{
    return oe_public_key_read_pem(
        pem_data,
        pem_size,
        (oe_public_key_t*)private_key,
        MBEDTLS_PK_RSA,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_write_pem(
    const oe_rsa_public_key_t* private_key,
    uint8_t* pem_data,
    size_t* pem_size)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)private_key,
        pem_data,
        pem_size,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* private_key)
{
    return oe_private_key_free(
        (oe_private_key_t*)private_key, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* public_key)
{
    return oe_public_key_free((oe_public_key_t*)public_key, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_sign(
    const oe_rsa_private_key_t* private_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    uint8_t* signature,
    size_t* signature_size)
{
    return oe_private_key_sign(
        (oe_private_key_t*)private_key,
        hash_type,
        hash_data,
        hash_size,
        signature,
        signature_size,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_verify(
    const oe_rsa_public_key_t* public_key,
    oe_hash_type_t hash_type,
    const void* hash_data,
    size_t hash_size,
    const uint8_t* signature,
    size_t signature_size)
{
    return oe_public_key_verify(
        (oe_public_key_t*)public_key,
        hash_type,
        hash_data,
        hash_size,
        signature,
        signature_size,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    return oe_public_key_get_modulus(
        (oe_public_key_t*)public_key, buffer, buffer_size);
}

oe_result_t oe_rsa_public_key_get_exponent(
    const oe_rsa_public_key_t* public_key,
    uint8_t* buffer,
    size_t* buffer_size)
{
    return oe_public_key_get_exponent(
        (oe_public_key_t*)public_key, buffer, buffer_size);
}

oe_result_t oe_rsa_public_key_equal(
    const oe_rsa_public_key_t* public_key1,
    const oe_rsa_public_key_t* public_key2,
    bool* equal)
{
    return oe_public_key_equal(
        (oe_public_key_t*)public_key1, (oe_public_key_t*)public_key2, equal);
}
