// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <openenclave/internal/hexdump.h>
#include <openenclave/internal/raise.h>
#include <openenclave/internal/defs.h>
#include <openssl/obj_mac.h>
#include <openssl/pem.h>
#include <string.h>
#include "init.h"
#include "key.h"

/* Magic numbers for the EC key implementation structures */
static const uint64_t _PRIVATE_KEY_MAGIC = 0x19a751419ae04bbc;
static const uint64_t _PUBLIC_KEY_MAGIC = 0xb1d39580c1f14c02;

OE_STATIC_ASSERT(sizeof(oe_public_key_t) <= sizeof(oe_ec_public_key_t));
OE_STATIC_ASSERT(sizeof(oe_private_key_t) <= sizeof(oe_ec_private_key_t));

static int _GetNID(oe_ec_type_t ecType)
{
    switch (ecType)
    {
        case OE_EC_TYPE_SECP256R1:
            return NID_X9_62_prime256v1;
        default:
            return NID_undef;
    }
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
    oe_ec_type_t ecType,
    oe_private_key_t* privateKey,
    oe_public_key_t* publicKey)
{
    oe_result_t result = OE_UNEXPECTED;
    int nid;
    EC_KEY* ecPrivate = NULL;
    EC_KEY* ecPublic = NULL;
    EVP_PKEY* pkeyPrivate = NULL;
    EVP_PKEY* pkeyPublic = NULL;
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

    /* Get the NID for this curve type */
    if ((nid = _GetNID(ecType)) == NID_undef)
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
    return oe_public_key_init(
        (oe_public_key_t*)publicKey, pkey, _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_read_pem(
    oe_ec_private_key_t* privateKey,
    const uint8_t* pemData,
    size_t pemSize)
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
    oe_ec_public_key_t* publicKey,
    const uint8_t* pemData,
    size_t pemSize)
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
        (const oe_public_key_t*)privateKey,
        pemData,
        pemSize,
        _PUBLIC_KEY_MAGIC);
}

oe_result_t oe_ec_private_key_free(oe_ec_private_key_t* privateKey)
{
    return oe_private_key_free(
        (oe_private_key_t*)privateKey, _PRIVATE_KEY_MAGIC);
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

oe_result_t oe_ec_public_key_equal(
    const oe_ec_public_key_t* publicKey1,
    const oe_ec_public_key_t* publicKey2,
    bool* equal)
{
    return _PublicKeyEqual(
        (oe_public_key_t*)publicKey1, (oe_public_key_t*)publicKey2, equal);
}

oe_result_t oe_ec_public_key_from_coordinates(
    oe_ec_public_key_t* publicKey,
    oe_ec_type_t ecType,
    const uint8_t* xData,
    size_t xSize,
    const uint8_t* yData,
    size_t ySize)
{
    oe_result_t result = OE_UNEXPECTED;
    oe_public_key_t* impl = (oe_public_key_t*)publicKey;
    int nid;
    EC_KEY* ec = NULL;
    EVP_PKEY* pkey = NULL;
    EC_GROUP* group = NULL;
    EC_POINT* point = NULL;
    BIGNUM* x = NULL;
    BIGNUM* y = NULL;

    if (publicKey)
        memset(publicKey, 0, sizeof(oe_ec_public_key_t));

    /* Initialize OpenSSL */
    oe_initialize_openssl();

    /* Reject invalid parameters */
    if (!publicKey || !xData || !xSize || !yData || !ySize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the NID for this curve type */
    if ((nid = _GetNID(ecType)) == NID_undef)
        OE_RAISE(OE_FAILURE);

    /* Create the public EC key */
    {
        if (!(group = EC_GROUP_new_by_curve_name(nid)))
            OE_RAISE(OE_FAILURE);

        if (!(ec = EC_KEY_new()))
            OE_RAISE(OE_FAILURE);

        if (!(EC_KEY_set_group(ec, group)))
            OE_RAISE(OE_FAILURE);

        if (!(point = EC_POINT_new(group)))
            OE_RAISE(OE_FAILURE);

        if (!(x = BN_new()) || !(y = BN_new()))
            OE_RAISE(OE_FAILURE);

        if (!(BN_bin2bn(xData, xSize, x)))
            OE_RAISE(OE_FAILURE);

        if (!(BN_bin2bn(yData, ySize, y)))
            OE_RAISE(OE_FAILURE);

        if (!EC_POINT_set_affine_coordinates_GFp(group, point, x, y, NULL))
            OE_RAISE(OE_FAILURE);

        if (!EC_KEY_set_public_key(ec, point))
            OE_RAISE(OE_FAILURE);

        point = NULL;
    }

    /* Create the PKEY public key wrapper */
    {
        /* Create the public key structure */
        if (!(pkey = EVP_PKEY_new()))
            OE_RAISE(OE_FAILURE);

        /* Initialize the public key from the generated key pair */
        {
            if (!EVP_PKEY_assign_EC_KEY(pkey, ec))
                OE_RAISE(OE_FAILURE);

            ec = NULL;
        }

        /* Initialize the public key */
        {
            oe_public_key_init(impl, pkey, _PUBLIC_KEY_MAGIC);
            pkey = NULL;
        }
    }

    result = OE_OK;

done:

    if (ec)
        EC_KEY_free(ec);

    if (group)
        EC_GROUP_free(group);

    if (pkey)
        EVP_PKEY_free(pkey);

    if (x)
        BN_free(x);

    if (y)
        BN_free(y);

    if (point)
        EC_POINT_free(point);

    return result;
}

oe_result_t oe_ecdsa_signature_write_der(
    unsigned char* signature,
    size_t* signatureSize,
    const uint8_t* rData,
    size_t rSize,
    const uint8_t* sData,
    size_t sSize)
{
    oe_result_t result = OE_UNEXPECTED;
    ECDSA_SIG* sig = NULL;
    int sigLen;

    /* Reject invalid parameters */
    if (!signatureSize || !rData || !rSize || !sData || !sSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature is null, then signatureSize must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Create new signature object */
    if (!(sig = ECDSA_SIG_new()))
        OE_RAISE(OE_FAILURE);

    /* Convert R to big number object */
    if (!(BN_bin2bn(rData, rSize, sig->r)))
        OE_RAISE(OE_FAILURE);

    /* Convert S to big number object */
    if (!(BN_bin2bn(sData, sSize, sig->s)))
        OE_RAISE(OE_FAILURE);

    /* Determine the size of the binary signature */
    if ((sigLen = i2d_ECDSA_SIG(sig, NULL)) <= 0)
        OE_RAISE(OE_FAILURE);

    /* Copy binary signature to output buffer */
    if (signature && sigLen <= *signatureSize)
    {
        uint8_t* p = signature;

        if (!i2d_ECDSA_SIG(sig, &p))
            OE_RAISE(OE_FAILURE);

        if (p - signature != sigLen)
            OE_RAISE(OE_FAILURE);
    }

    /* Check whether buffer is too small */
    if (sigLen > *signatureSize)
    {
        *signatureSize = sigLen;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Set the size of the output buffer */
    *signatureSize = sigLen;

    result = OE_OK;

done:

    if (sig)
        ECDSA_SIG_free(sig);

    return result;
}
