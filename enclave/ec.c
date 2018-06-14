// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include "key.h"
#include "pem.h"
#include "random.h"

static uint64_t _PRIVATE_KEY_MAGIC = 0xf12c37bb02814eeb;
static uint64_t _PUBLIC_KEY_MAGIC = 0xd7490a56f6504ee6;

OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_ec_private_key_t));
OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_ec_public_key_t));

/* Curve names, indexed by oe_ec_type_t */
static const char* _curveNames[] = {
    "secp521r1" /* OE_EC_TYPE_SECP521R1 */
};

/* Convert ECType to curve name */
static const char* _ECTypeToString(oe_type_t type)
{
    size_t index = (size_t)type;

    if (index >= OE_COUNTOF(_curveNames))
        return NULL;

    return _curveNames[index];
}

static oe_result_t _CopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields)
{
    oe_result_t result = OE_UNEXPECTED;
    const mbedtls_pk_info_t* info;

    if (dest)
        mbedtls_pk_init(dest);

    /* Check parameters */
    if (!dest || !src)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Lookup the info for this key type */
    if (!(info = mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)))
        OE_RAISE(OE_WRONG_TYPE);

    /* Setup the context for this key type */
    if (mbedtls_pk_setup(dest, info) != 0)
        OE_RAISE(OE_FAILURE);

    /* Copy all fields of the key structure */
    {
        mbedtls_ecp_keypair* ecDest = mbedtls_pk_ec(*dest);
        const mbedtls_ecp_keypair* ecSrc = mbedtls_pk_ec(*src);

        if (!ecDest || !ecSrc)
            OE_RAISE(OE_FAILURE);

        if (mbedtls_ecp_group_copy(&ecDest->grp, &ecSrc->grp) != 0)
            OE_RAISE(OE_FAILURE);

        if (copyPrivateFields)
        {
            if (mbedtls_mpi_copy(&ecDest->d, &ecSrc->d) != 0)
                OE_RAISE(OE_FAILURE);
        }

        if (mbedtls_ecp_copy(&ecDest->Q, &ecSrc->Q) != 0)
            OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:

    if (result != OE_OK)
        mbedtls_pk_free(dest);

    return result;
}

static oe_result_t _GenerateKeyPair(
    oe_ec_type_t type,
    oe_private_key_t* privateKey,
    oe_public_key_t* publicKey)
{
    oe_result_t result = OE_UNEXPECTED;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;
    int curve;
    const char* curveName;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    if (privateKey)
        oe_memset(privateKey, 0, sizeof(*privateKey));

    if (publicKey)
        oe_memset(publicKey, 0, sizeof(*publicKey));

    /* Check for invalid parameters */
    if (!privateKey || !publicKey)
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
    if (!(drbg = oe_mbedtls_get_drbg()))
        OE_RAISE(OE_FAILURE);

    /* Create key struct */
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Generate the EC key */
    if (mbedtls_ecp_gen_key(
            curve, mbedtls_pk_ec(pk), mbedtls_ctr_drbg_random, drbg) != 0)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Initialize the private key parameter */
    OE_CHECK(oe_private_key_init(privateKey, &pk, _CopyKey, _PRIVATE_KEY_MAGIC));

    /* Initialize the public key parameter */
    OE_CHECK(oe_public_key_init(publicKey, &pk, _CopyKey, _PUBLIC_KEY_MAGIC));

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        oe_private_key_free(privateKey, _PRIVATE_KEY_MAGIC);
        oe_public_key_free(publicKey, _PUBLIC_KEY_MAGIC);
    }

    return result;
}

static oe_result_t oe_public_key_get_key_bytes(
    const oe_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    oe_result_t result = OE_UNEXPECTED;

    /* Check for invalid parameters */
    if (!publicKey || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then bufferSize should be zero */
    if (!buffer && *bufferSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert public EC key to binary */
    {
        const mbedtls_ecp_keypair* ec = mbedtls_pk_ec(publicKey->pk);
        uint8_t scratch[1];
        uint8_t* data;
        size_t size;
        size_t requiredSize;

        if (!ec)
            OE_RAISE(OE_FAILURE);

        if (buffer == NULL || *bufferSize == 0)
        {
            // mbedtls_ecp_point_write_binary() needs a non-null buffer longer
            // than zero to correctly calculate the required buffer size.
            data = scratch;
            size = 1;
        }
        else
        {
            data = buffer;
            size = *bufferSize;
        }

        int r = mbedtls_ecp_point_write_binary(
            &ec->grp,
            &ec->Q,
            MBEDTLS_ECP_PF_UNCOMPRESSED,
            &requiredSize,
            data,
            size);

        *bufferSize = requiredSize;

        if (r == MBEDTLS_ERR_ECP_BUFFER_TOO_SMALL)
            OE_RAISE(OE_BUFFER_TOO_SMALL);

        if (r != 0)
            OE_RAISE(OE_FAILURE);
    }

    result = OE_OK;

done:

    return result;
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

    /* Compare the groups and EC points */
    {
        const mbedtls_ecp_keypair* ec1 = mbedtls_pk_ec(publicKey1->pk);
        const mbedtls_ecp_keypair* ec2 = mbedtls_pk_ec(publicKey2->pk);

        if (!ec1 || !ec2)
            OE_RAISE(OE_INVALID_PARAMETER);

        if (ec1->grp.id == ec2->grp.id &&
            mbedtls_ecp_point_cmp(&ec1->Q, &ec2->Q) == 0)
        {
            *equal = true;
        }
    }

    result = OE_OK;

done:
    return result;
}

oe_result_t oe_ec_public_key_init(
    oe_ec_public_key_t* publicKey,
    const mbedtls_pk_context* pk)
{
    return oe_public_key_init(
        (oe_public_key_t*)publicKey, pk, _CopyKey, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_ec_private_key_t* privateKey)
{
    return oe_private_key_read_pem(
        pemData,
        pemSize,
        (oe_private_key_t*)privateKey,
        MBEDTLS_PK_ECKEY,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_write_pem(
    const oe_ec_private_key_t* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return oe_private_key_write_pem(
        (const oe_private_key_t*)privateKey, pemData, pemSize, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_ec_public_key_t* privateKey)
{
    return oe_public_key_read_pem(
        pemData,
        pemSize,
        (oe_public_key_t*)privateKey,
        MBEDTLS_PK_ECKEY,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_write_pem(
    const oe_ec_public_key_t* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return oe_public_key_write_pem(
        (const oe_public_key_t*)privateKey, pemData, pemSize, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_free(oe_ec_private_key_t* privateKey)
{
    return oe_private_key_free((oe_private_key_t*)privateKey, _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_free(oe_ec_public_key_t* publicKey)
{
    return oe_public_key_free((oe_public_key_t*)publicKey, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_sign(
    const oe_ec_private_key_t* privateKey,
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

oe_result_t oe_ec_public_key_verify(
    const oe_ec_public_key_t* publicKey,
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

oe_result_t oe_ec_generate_key_pair(
    oe_ec_type_t type,
    oe_ec_private_key_t* privateKey,
    oe_ec_public_key_t* publicKey)
{
    return _GenerateKeyPair(
        type, (oe_private_key_t*)privateKey, (oe_public_key_t*)publicKey);
}

oe_result_t oe_ec_public_key_get_key_bytes(
    const oe_ec_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return oe_public_key_get_key_bytes(
        (oe_public_key_t*)publicKey, buffer, bufferSize);
}

oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* publicKey1,
    const oe_ec_public_key_t* publicKey2,
    bool* equal)
{
    return oe_public_key_equal(
        (oe_public_key_t*)publicKey1, (oe_public_key_t*)publicKey2, equal);
}
