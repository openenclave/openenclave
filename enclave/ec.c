// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/raise.h>
#include "pem.h"
#include "random.h"

static OE_Result _CopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields);

static const uint64_t PRIVATE_KEY_MAGIC = 0xf12c37bb02814eeb;
static const uint64_t PUBLIC_KEY_MAGIC = 0xd7490a56f6504ee6;
static const mbedtls_pk_type_t MBEDTLS_PK_KEYTYPE = MBEDTLS_PK_ECKEY;
#include "key.c"

OE_STATIC_ASSERT(sizeof(PrivateKey) <= sizeof(OE_ECPrivateKey));
OE_STATIC_ASSERT(sizeof(PublicKey) <= sizeof(OE_ECPublicKey));

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

OE_Result OE_ECGenerateKeyPair(
    OE_ECType type,
    OE_ECPrivateKey* privateKey,
    OE_ECPublicKey* publicKey)
{
    PrivateKey* privateKeyImpl = (PrivateKey*)privateKey;
    PublicKey* publicKeyImpl = (PublicKey*)publicKey;
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
    OE_CHECK(_PrivateKeyInit(privateKeyImpl, &pk));

    /* Initialize the public key parameter */
    OE_CHECK(_PublicKeyInit(publicKeyImpl, &pk));

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        if (_PrivateKeyValid(privateKeyImpl))
            _PrivateKeyFree(privateKeyImpl);

        if (_PublicKeyValid(publicKeyImpl))
            _PublicKeyFree(publicKeyImpl);
    }

    return result;
}

OE_Result OE_ECPublicKeyGetKeyBytes(
    const OE_ECPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    const PublicKey* impl = (const PublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    /* Check for invalid parameters */
    if (!publicKey || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then bufferSize should be zero */
    if (!buffer && *bufferSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Convert public EC key to binary */
    {
        const mbedtls_ecp_keypair* ec = mbedtls_pk_ec(impl->pk);
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

OE_Result OE_ECPublicKeyEqual(
    const OE_ECPublicKey* publicKey1,
    const OE_ECPublicKey* publicKey2,
    bool* equal)
{
    const PublicKey* impl1 = (const PublicKey*)publicKey1;
    const PublicKey* impl2 = (const PublicKey*)publicKey2;
    OE_Result result = OE_UNEXPECTED;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!_PublicKeyValid(impl1) || !_PublicKeyValid(impl2) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Compare the exponent and modulus */
    {
        const mbedtls_ecp_keypair* ec1 = mbedtls_pk_ec(impl1->pk);
        const mbedtls_ecp_keypair* ec2 = mbedtls_pk_ec(impl2->pk);

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
    return _PublicKeyInit((PublicKey*)publicKey, pk);
}

OE_Result OE_ECPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPrivateKey* privateKey)
{
    return _PrivateKeyReadPEM(pemData, pemSize, (PrivateKey*)privateKey);
}

OE_Result OE_ECPrivateKeyWritePEM(
    const OE_ECPrivateKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return _PrivateKeyWritePEM((const PrivateKey*)privateKey, pemData, pemSize);
}

OE_Result OE_ECPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPublicKey* privateKey)
{
    return _PublicKeyReadPEM(pemData, pemSize, (PublicKey*)privateKey);
}

OE_Result OE_ECPublicKeyWritePEM(
    const OE_ECPublicKey* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return _PublicKeyWritePEM((const PublicKey*)privateKey, pemData, pemSize);
}

OE_Result OE_ECPrivateKeyFree(OE_ECPrivateKey* privateKey)
{
    return _PrivateKeyFree((PrivateKey*)privateKey);
}

OE_Result OE_ECPublicKeyFree(OE_ECPublicKey* publicKey)
{
    return _PublicKeyFree((PublicKey*)publicKey);
}

OE_Result OE_ECPrivateKeySign(
    const OE_ECPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    return _PrivateKeySign(
        (PrivateKey*)privateKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize);
}

OE_Result OE_ECPublicKeyVerify(
    const OE_ECPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    return _PublicKeyVerify(
        (PublicKey*)publicKey,
        hashType,
        hashData,
        hashSize,
        signature,
        signatureSize);
}
