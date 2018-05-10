// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include "pem.h"
#include "random.h"
#include "key.h"

static uint64_t _PRIVATE_KEY_MAGIC = 0xf12c37bb02814eeb;
static uint64_t _PUBLIC_KEY_MAGIC = 0xd7490a56f6504ee6;

OE_STATIC_ASSERT(sizeof(OE_PrivateKey) <= sizeof(OE_ECPrivateKey));
OE_STATIC_ASSERT(sizeof(OE_PublicKey) <= sizeof(OE_ECPublicKey));

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

static OE_Result _CopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields)
{
    OE_Result result = OE_UNEXPECTED;
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

static OE_Result _GenerateKeyPair(
    OE_ECType type,
    OE_PrivateKey* privateKey,
    OE_PublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;
    int curve;
    const char* curveName;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    if (privateKey)
        OE_Memset(privateKey, 0, sizeof(*privateKey));

    if (publicKey)
        OE_Memset(publicKey, 0, sizeof(*publicKey));

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
    if (!(drbg = OE_MBEDTLS_GetDrbg()))
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
    OE_CHECK(OE_PrivateKeyInit(privateKey, &pk, _CopyKey, _PRIVATE_KEY_MAGIC));

    /* Initialize the public key parameter */
    OE_CHECK(OE_PublicKeyInit(publicKey, &pk, _CopyKey, _PUBLIC_KEY_MAGIC));

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        OE_PrivateKeyFree(privateKey, _PRIVATE_KEY_MAGIC);
        OE_PublicKeyFree(publicKey, _PUBLIC_KEY_MAGIC);
    }

    return result;
}

static OE_Result OE_PublicKeyGetKeyBytes(
    const OE_PublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    OE_Result result = OE_UNEXPECTED;

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

static OE_Result OE_PublicKeyEqual(
    const OE_PublicKey* publicKey1,
    const OE_PublicKey* publicKey2,
    bool* equal)
{
    OE_Result result = OE_UNEXPECTED;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!OE_PublicKeyValid(publicKey1, _PUBLIC_KEY_MAGIC) || !OE_PublicKeyValid(publicKey2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Compare the exponent and modulus */
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

OE_Result OE_ECPublicKeyInit(
    OE_ECPublicKey* publicKey,
    const mbedtls_pk_context* pk)
{
    return OE_PublicKeyInit((OE_PublicKey*)publicKey, pk, _CopyKey, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPrivateKey* privateKey)
{
    return OE_PrivateKeyReadPEM(pemData, pemSize, (OE_PrivateKey*)privateKey,
        MBEDTLS_PK_ECKEY, _PRIVATE_KEY_MAGIC);
}

OE_Result OE_ECPrivateKeyWritePEM(
    const OE_ECPrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return OE_PrivateKeyWritePEM((const OE_PrivateKey*)privateKey, pemData, pemSize, _PRIVATE_KEY_MAGIC);
}

OE_Result OE_ECPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPublicKey* privateKey)
{
    return OE_PublicKeyReadPEM(pemData, pemSize, (OE_PublicKey*)privateKey,
        MBEDTLS_PK_ECKEY, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECPublicKeyWritePEM(
    const OE_ECPublicKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return OE_PublicKeyWritePEM((const OE_PublicKey*)privateKey, pemData, pemSize, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECPrivateKeyFree(OE_ECPrivateKey* privateKey)
{
    return OE_PrivateKeyFree((OE_PrivateKey*)privateKey, _PRIVATE_KEY_MAGIC);
}

OE_Result OE_ECPublicKeyFree(OE_ECPublicKey* publicKey)
{
    return OE_PublicKeyFree((OE_PublicKey*)publicKey, _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECPrivateKeySign(
    const OE_ECPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    return OE_PrivateKeySign(
        (OE_PrivateKey*)privateKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize, 
        _PRIVATE_KEY_MAGIC);
}

OE_Result OE_ECPublicKeyVerify(
    const OE_ECPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    return OE_PublicKeyVerify(
        (OE_PublicKey*)publicKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize,
        _PUBLIC_KEY_MAGIC);
}

OE_Result OE_ECGenerateKeyPair(
    OE_ECType type,
    OE_ECPrivateKey* privateKey,
    OE_ECPublicKey* publicKey)
{
    return _GenerateKeyPair(type, (OE_PrivateKey*)privateKey, (OE_PublicKey*)publicKey);
}

OE_Result OE_ECPublicKeyGetKeyBytes(
    const OE_ECPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return OE_PublicKeyGetKeyBytes((OE_PublicKey*)publicKey, buffer, bufferSize);
}

OE_Result OE_ECPublicKeyEqual(
    const OE_ECPublicKey* publicKey1,
    const OE_ECPublicKey* publicKey2,
    bool* equal)
{
    return OE_PublicKeyEqual((OE_PublicKey*)publicKey1, (OE_PublicKey*)publicKey2, equal);
}
