// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <openenclave/bits/raise.h>
#include <openssl/pem.h>
#include <string.h>
#include "init.h"
#include "key.h"

/* Magic numbers for the EC key implementation structures */
static const uint64_t _PRIVATE_KEY_MAGIC = 0x19a751419ae04bbc;
static const uint64_t _PUBLIC_KEY_MAGIC = 0xb1d39580c1f14c02;

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_ec_public_key_t));
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

static oe_result_t _privateKeyWritePEMCallback(BIO* bio, EVP_PKEY* pkey)
{
    oe_result_t result = OE_UNEXPECTED;
    EC_KEY* ec = NULL;

    if (!(ec = EVP_PKEY_get1_EC_KEY(pkey)))
        OE_RAISE(OE_FAILURE);

    if (!PEM_write_bio_ECPrivateKey(bio, ec, NULL, NULL, 0, 0, NULL))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (ec)
        EC_KEY_free(ec);

    return result;
}

static oe_result_t _GenerateKeyPair(
    oe_ec_type_t type,
    oe_private_key_t* privateKey,
    oe_public_key_t* publicKey)
{
    oe_result_t result = OE_UNEXPECTED;
    int nid;
    EC_KEY* ecPrivate = NULL;
    EC_KEY* ecPublic = NULL;
    EVP_PKEY* pkeyPrivate = NULL;
    EVP_PKEY* pkeyPublic = NULL;
    const char* curveName;
    EC_POINT* point = NULL;

    if (privateKey)
        memset(privateKey, 0, sizeof(*privateKey));

    if (publicKey)
        memset(publicKey, 0, sizeof(*publicKey));

    /* Check parameters */
    if (!privateKey || !publicKey)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Initialize OpenSSL */
    oe_initialize_openssl();

    /* Get the curve name for this EC key type */
    if (!(curveName = _ECTypeToString(type)))
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Resolve the NID for this curve name */
    if ((nid = OBJ_txt2nid(curveName)) == NID_undef)
        OE_RAISE(OE_FAILURE);

    /* Create the private EC key */
    {
        /* Create the private key */
        if (!(ecPrivate = EC_KEY_new_by_curve_name(nid)))
            OE_RAISE(OE_FAILURE);

        /* Set the EC named-curve flag */
        EC_KEY_set_asn1_flag(ecPrivate, OPENSSL_EC_NAMED_CURVE);

        /* Generate the public/private key pair */
        if (!EC_KEY_generate_key(ecPrivate))
            OE_RAISE(OE_FAILURE);
    }

    /* Create the public EC key */
    {
        /* Create the public key */
        if (!(ecPublic = EC_KEY_new_by_curve_name(nid)))
            OE_RAISE(OE_FAILURE);

        /* Set the EC named-curve flag */
        EC_KEY_set_asn1_flag(ecPublic, OPENSSL_EC_NAMED_CURVE);

        /* Duplicate public key point from the private key */
        if (!(point = EC_POINT_dup(
                  EC_KEY_get0_public_key(ecPrivate),
                  EC_KEY_get0_group(ecPublic))))
        {
            OE_RAISE(OE_FAILURE);
        }

        /* Set the public key */
        if (!EC_KEY_set_public_key(ecPublic, point))
            OE_RAISE(OE_FAILURE);

        /* Keep from being freed below */
        point = NULL;
    }

    /* Create the PKEY private key wrapper */
    {
        /* Create the private key structure */
        if (!(pkeyPrivate = EVP_PKEY_new()))
            OE_RAISE(OE_FAILURE);

        /* Initialize the private key from the generated key pair */
        if (!EVP_PKEY_assign_EC_KEY(pkeyPrivate, ecPrivate))
            OE_RAISE(OE_FAILURE);

        /* Initialize the private key */
        oe_private_key_init(privateKey, pkeyPrivate, _PRIVATE_KEY_MAGIC);

        /* Keep these from being freed below */
        ecPrivate = NULL;
        pkeyPrivate = NULL;
    }

    /* Create the PKEY public key wrapper */
    {
        /* Create the public key structure */
        if (!(pkeyPublic = EVP_PKEY_new()))
            OE_RAISE(OE_FAILURE);

        /* Initialize the public key from the generated key pair */
        if (!EVP_PKEY_assign_EC_KEY(pkeyPublic, ecPublic))
            OE_RAISE(OE_FAILURE);

        /* Initialize the public key */
        oe_public_key_init(publicKey, pkeyPublic, _PUBLIC_KEY_MAGIC);

        /* Keep these from being freed below */
        ecPublic = NULL;
        pkeyPublic = NULL;
    }

    result = OE_OK;

done:

    if (ecPrivate)
        EC_KEY_free(ecPrivate);

    if (ecPublic)
        EC_KEY_free(ecPublic);

    if (pkeyPrivate)
        EVP_PKEY_free(pkeyPrivate);

    if (pkeyPublic)
        EVP_PKEY_free(pkeyPublic);

    if (point)
        EC_POINT_free(point);

    if (result != OE_OK)
    {
        oe_private_key_free(privateKey, _PRIVATE_KEY_MAGIC);
        oe_public_key_free(publicKey, _PUBLIC_KEY_MAGIC);
    }

    return result;
}

static oe_result_t _PublicKeyGetKeyBytes(
    const oe_public_key_t* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    oe_result_t result = OE_UNEXPECTED;
    uint8_t* data = NULL;
    EC_KEY* ec = NULL;
    int requiredSize;

    /* Check for invalid parameters */
    if (!publicKey || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the EC public key */
    if (!(ec = EVP_PKEY_get1_EC_KEY(publicKey->pkey)))
        OE_RAISE(OE_FAILURE);

    /* Set the required buffer size */
    if ((requiredSize = i2o_ECPublicKey(ec, NULL)) == 0)
        OE_RAISE(OE_FAILURE);

    /* If buffer is null or not big enough */
    if (!buffer || (*bufferSize < requiredSize))
    {
        *bufferSize = requiredSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Get the key bytes */
    if (!i2o_ECPublicKey(ec, &data))
        OE_RAISE(OE_FAILURE);

    /* Copy to caller's buffer */
    memcpy(buffer, data, requiredSize);
    *bufferSize = requiredSize;

    result = OE_OK;

done:

    if (ec)
        EC_KEY_free(ec);

    if (data)
        free(data);

    return result;
}

static oe_result_t _PublicKeyEqual(
    const oe_public_key_t* publicKey1,
    const oe_public_key_t* publicKey2,
    bool* equal)
{
    oe_result_t result = OE_UNEXPECTED;
    EC_KEY* ec1 = NULL;
    EC_KEY* ec2 = NULL;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!oe_public_key_is_valid(publicKey1, _PUBLIC_KEY_MAGIC) ||
        !oe_public_key_is_valid(publicKey2, _PUBLIC_KEY_MAGIC) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    {
        ec1 = EVP_PKEY_get1_EC_KEY(publicKey1->pkey);
        ec2 = EVP_PKEY_get1_EC_KEY(publicKey2->pkey);
        const EC_GROUP* group1 = EC_KEY_get0_group(ec1);
        const EC_GROUP* group2 = EC_KEY_get0_group(ec2);
        const EC_POINT* point1 = EC_KEY_get0_public_key(ec1);
        const EC_POINT* point2 = EC_KEY_get0_public_key(ec2);

        if (!ec1 || !ec2 || !group1 || !group2 || !point1 || !point2)
            OE_RAISE(OE_FAILURE);

        /* Compare group and public key point */
        if (EC_GROUP_cmp(group1, group2, NULL) == 0 &&
            EC_POINT_cmp(group1, point1, point2, NULL) == 0)
        {
            *equal = true;
        }
    }

    result = OE_OK;

done:

    if (ec1)
        EC_KEY_free(ec1);

    if (ec2)
        EC_KEY_free(ec2);

    return result;
}

void oe_ec_public_key_init(oe_ec_public_key_t* publicKey, EVP_PKEY* pkey)
{
    return oe_public_key_init((oe_public_key_t*)publicKey, pkey, _PUBLIC_KEY_MAGIC);
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
        EVP_PKEY_EC,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_write_pem(
    const oe_ec_private_key_t* privateKey,
    uint8_t* pemData,
    size_t* pemSize)
{
    return oe_private_key_write_pem(
        (const oe_private_key_t*)privateKey,
        pemData,
        pemSize,
        _privateKeyWritePEMCallback,
        _PRIVATE_KEY_MAGIC);
}

oe_result_t oe_ec_public_key_read_pem(
    const uint8_t* pemData,
    size_t pemSize,
    oe_ec_public_key_t* publicKey)
{
    return oe_public_key_read_pem(
        pemData,
        pemSize,
        (oe_public_key_t*)publicKey,
        EVP_PKEY_EC,
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
    return _PublicKeyGetKeyBytes((oe_public_key_t*)publicKey, buffer, bufferSize);
}

oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* publicKey1,
    const oe_ec_public_key_t* publicKey2,
    bool* equal)
{
    return _PublicKeyEqual(
        (oe_public_key_t*)publicKey1, (oe_public_key_t*)publicKey2, equal);
}
