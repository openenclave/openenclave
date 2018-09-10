// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "rsa.h"
#include <openenclave/internal/enclavelibc.h>
#include <openenclave/internal/raise.h>
#include "key.h"
#include "pem.h"
#include "random.h"

static uint64_t _PRIVATE_KEY_MAGIC = 0xd48de5bae3994b41;
static uint64_t _PUBLIC_KEY_MAGIC = 0x713600af058c447a;

OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_rsa_private_key_t));
OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_rsa_public_key_t));

static oe_result_t _CopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields)
{
    oe_result_t result = OE_UNEXPECTED;
    const mbedtls_pk_info_t* info;
    mbedtls_rsa_context* rsa;

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
        OE_RAISE(OE_FAILURE);

    /* Setup the context for this key type */
    if (mbedtls_pk_setup(dest, info) != 0)
        OE_RAISE(OE_FAILURE);

    /* Get the context for this key type */
    if (!(rsa = dest->pk_ctx))
        OE_RAISE(OE_FAILURE);

    /* Initialize the RSA key from the source */
    if (mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(*src)) != 0)
        OE_RAISE(OE_FAILURE);

    /* If not a private key, then clear private key fields */
    if (!copyPrivateFields)
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

static oe_result_t _GetPublicKeyModulusOrExponent(
    const oe_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize,
    bool getModulus)
{
    oe_result_t result = OE_UNEXPECTED;
    size_t requiredSize;
    mbedtls_rsa_context* rsa;
    const mbedtls_mpi* mpi;

    /* Check for invalid parameters */
    if (!oe_public_key_is_valid(publicKey, _PUBLIC_KEY_MAGIC) || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then bufferSize must be zero */
    if (!buffer && *bufferSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the RSA context */
    if (!(rsa = publicKey->pk.pk_ctx))
        OE_RAISE(OE_FAILURE);

    /* Pick modulus or exponent */
    if (!(mpi = getModulus ? &rsa->N : &rsa->E))
        OE_RAISE(OE_FAILURE);

    /* Determine the required size in bytes */
    requiredSize = mbedtls_mpi_size(mpi);

    /* If buffer is null or not big enough */
    if (!buffer || (*bufferSize < requiredSize))
    {
        *bufferSize = requiredSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy key bytes to the caller's buffer */
    if (mbedtls_mpi_write_binary(mpi, buffer, requiredSize) != 0)
        OE_RAISE(OE_FAILURE);

    *bufferSize = requiredSize;

    result = OE_OK;

done:

    return result;
}

static oe_result_t _GenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    oe_private_key_t* privateKey,
    oe_public_key_t* publicKey)
{
    oe_result_t result = OE_UNEXPECTED;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    if (privateKey)
        oe_memset(privateKey, 0, sizeof(*privateKey));

    if (publicKey)
        oe_memset(publicKey, 0, sizeof(*publicKey));

    /* Check for invalid parameters */
    if (!privateKey || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check range of bits and exponent parameters */
    if (bits > OE_UINT_MAX || exponent > OE_INT_MAX)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the random number generator */
    if (!(drbg = oe_mbedtls_get_drbg()))
        OE_RAISE(OE_FAILURE);

    /* Create key struct */
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
        OE_RAISE(OE_FAILURE);

    /* Generate the RSA key */
    if (mbedtls_rsa_gen_key(
            mbedtls_pk_rsa(pk),
            mbedtls_ctr_drbg_random,
            drbg,
            bits,
            exponent) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    /* Initialize the private key parameter */
    OE_CHECK(
        oe_private_key_init(privateKey, &pk, _CopyKey, _PRIVATE_KEY_MAGIC));

    /* Initialize the public key parameter */
    OE_CHECK(oe_public_key_init(publicKey, &pk, _CopyKey, _PUBLIC_KEY_MAGIC));

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        if (oe_private_key_is_valid(privateKey, _PRIVATE_KEY_MAGIC))
            oe_private_key_free(privateKey, _PRIVATE_KEY_MAGIC);

        if (oe_public_key_is_valid(publicKey, _PUBLIC_KEY_MAGIC))
            oe_public_key_free(publicKey, _PUBLIC_KEY_MAGIC);
    }

    return result;
}

oe_result_t oe_public_key_get_modulus(
    const oe_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyModulusOrExponent(publicKey, buffer, bufferSize, true);
}

oe_result_t oe_public_key_get_exponent(
    const oe_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyModulusOrExponent(publicKey, buffer, bufferSize, false);
}

static oe_result_t oe_public_key_equal(
    const oe_public_key_t* publicKey1,
    const oe_public_key_t* publicKey2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!oe_public_key_is_valid(publicKey1, _PUBLIC_KEY_MAGIC) ||
        !oe_public_key_is_valid(publicKey2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Compare the exponent and modulus */
    {
        const mbedtls_rsa_context* rsa1 = publicKey1->pk.pk_ctx;
        const mbedtls_rsa_context* rsa2 = publicKey2->pk.pk_ctx;

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
    oe_rsa_public_key_t* publicKey,
    const mbedtls_pk_context* pk)
{
    return oe_public_key_init(
        (oe_public_key_t*)publicKey, pk, _CopyKey, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_read_pem(
    oe_rsa_private_key_t* privateKey,
    const uint8_t* pemData,
    size_t pemSize)
{
    return oe_private_key_read_pem(
        pemData,
        pemSize,
        (oe_private_key_t*)privateKey,
        MBEDTLS_PK_RSA,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_write_pem(
    const oe_rsa_private_key_t* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return oe_private_key_write_pem(
        (const oe_private_key_t*)privateKey,
        pemData,
        pemSize,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_read_pem(
    oe_rsa_public_key_t* privateKey,
    const uint8_t* pemData,
    size_t pemSize)
{
    return oe_public_key_read_pem(
        pemData,
        pemSize,
        (oe_public_key_t*)privateKey,
        MBEDTLS_PK_RSA,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_write_pem(
    const oe_rsa_public_key_t* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)privateKey,
        pemData,
        pemSize,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_free(oe_rsa_private_key_t* privateKey)
{
    return oe_private_key_free(
        (oe_private_key_t*)privateKey, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_free(oe_rsa_public_key_t* publicKey)
{
    return oe_public_key_free((oe_public_key_t*)publicKey, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_private_key_sign(
    const oe_rsa_private_key_t* privateKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    return oe_private_key_sign(
        (oe_private_key_t*)privateKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_rsa_public_key_verify(
    const oe_rsa_public_key_t* publicKey,
    oe_hash_type_t hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    return oe_public_key_verify(
        (oe_public_key_t*)publicKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_rsa_generate_key_pair(
    uint64_t bits,
    uint64_t exponent,
    oe_rsa_private_key_t* privateKey,
    oe_rsa_public_key_t* publicKey)
{
    return _GenerateKeyPair(
        bits,
        exponent,
        (oe_private_key_t*)privateKey,
        (oe_public_key_t*)publicKey);
}

oe_result_t oe_rsa_public_key_get_modulus(
    const oe_rsa_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return oe_public_key_get_modulus(
        (oe_public_key_t*)publicKey, buffer, bufferSize);
}

oe_result_t oe_rsa_public_key_get_exponent(
    const oe_rsa_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return oe_public_key_get_exponent(
        (oe_public_key_t*)publicKey, buffer, bufferSize);
}

oe_result_t oe_rsa_public_key_equal(
    const oe_rsa_public_key_t* publicKey1,
    const oe_rsa_public_key_t* publicKey2,
    bool* equal)
{
    return oe_public_key_equal(
        (oe_public_key_t*)publicKey1, (oe_public_key_t*)publicKey2, equal);
}
