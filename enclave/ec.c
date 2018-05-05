// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "ec.h"
#include <assert.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <openenclave/bits/ec.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/pem.h>
#include <openenclave/bits/raise.h>
#include <openenclave/enclave.h>
#include "pem.h"
#include "random.h"

/*
**==============================================================================
**
** Local definitions
**
**==============================================================================
*/

static OE_Result _CopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool copyPrivateFields);

/* Randomly generated magic number */
#define OE_EC_PRIVATE_KEY_MAGIC 0xf12c37bb02814eeb

typedef struct _ECPrivateKey
{
    uint64_t magic;
    mbedtls_pk_context pk;
} ECPrivateKey;

OE_STATIC_ASSERT(sizeof(ECPrivateKey) <= sizeof(OE_ECPrivateKey));

OE_INLINE bool _ECPrivateKeyValid(const ECPrivateKey* impl)
{
    return impl && impl->magic == OE_EC_PRIVATE_KEY_MAGIC;
}

OE_INLINE void _ECPrivateKeyInit(ECPrivateKey* impl)
{
    impl->magic = OE_EC_PRIVATE_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _ECPrivateKeyFree(ECPrivateKey* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(ECPrivateKey));
    }
}

static OE_Result _ECPrivateKeyInitFrom(
    ECPrivateKey* impl, 
    const mbedtls_pk_context* pk)
{
    OE_Result result = OE_UNEXPECTED;

    _ECPrivateKeyInit(impl);

    if (!impl || !pk)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_CopyKey(&impl->pk, pk, true));

    result = OE_OK;

done:

    if (result != OE_OK)
        _ECPrivateKeyFree(impl);

    return result;
}

OE_INLINE void _ECPrivateKeyClear(ECPrivateKey* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(ECPrivateKey));
}

/* Randomly generated magic number */
#define OE_EC_PUBLIC_KEY_MAGIC 0xd7490a56f6504ee6

typedef struct _ECPublicKey
{
    uint64_t magic;
    mbedtls_pk_context pk;
} ECPublicKey;

OE_STATIC_ASSERT(sizeof(ECPublicKey) <= sizeof(OE_ECPublicKey));

OE_INLINE void _ECPublicKeyInit(ECPublicKey* impl)
{
    impl->magic = OE_EC_PUBLIC_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE bool _ECPublicKeyValid(const ECPublicKey* impl)
{
    return impl && impl->magic == OE_EC_PUBLIC_KEY_MAGIC;
}

OE_INLINE void _ECPublicKeyFree(ECPublicKey* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(ECPublicKey));
    }
}

OE_INLINE void _ECPublicKeyClear(ECPublicKey* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(ECPublicKey));
}

static mbedtls_md_type_t _MapHashType(OE_HashType md)
{
    switch (md)
    {
        case OE_HASH_TYPE_SHA256:
            return MBEDTLS_MD_SHA256;
        case OE_HASH_TYPE_SHA512:
            return MBEDTLS_MD_SHA512;
    }

    /* Unreachable */
    return 0;
}

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

/*
**==============================================================================
**
** Shared functions:
**
**==============================================================================
*/

bool OE_IsECKey(const mbedtls_pk_context* pk)
{
    if (pk->pk_info != mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY))
        return false;

    return true;
}

OE_Result OE_ECPublicKeyInitFrom(
    OE_ECPublicKey* publicKey, 
    const mbedtls_pk_context* pk)
{
    ECPublicKey* impl = (ECPublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    _ECPublicKeyInit(impl);

    if (!impl || !pk)
        OE_RAISE(OE_INVALID_PARAMETER);

    OE_CHECK(_CopyKey(&impl->pk, pk, false));

    result = OE_OK;

done:

OE_Assert(_ECPublicKeyValid(impl));
    if (result != OE_OK)
        _ECPublicKeyFree(impl);
OE_Assert(_ECPublicKeyValid(impl));

    return result;
}

/*
**==============================================================================
**
** Public EC functions:
**
**==============================================================================
*/

OE_Result OE_ECPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPrivateKey* privateKey)
{
    OE_Result result = OE_UNEXPECTED;
    ECPrivateKey* impl = (ECPrivateKey*)privateKey;

    /* Initialize the key */
    if (impl)
        _ECPrivateKeyInit(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(&impl->pk, pemData, pemSize, NULL, 0) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain an EC key */
    if (!OE_IsECKey(&impl->pk))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _ECPrivateKeyFree(impl);

    return result;
}

OE_Result OE_ECPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_ECPublicKey* publicKey)
{
    ECPublicKey* impl = (ECPublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (impl)
        _ECPublicKeyInit(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(&impl->pk, pemData, pemSize) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain an EC key */
    if (!OE_IsECKey(&impl->pk))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _ECPublicKeyFree(impl);

    return result;
}

OE_Result OE_ECPrivateKeyWritePEM(
    const OE_ECPrivateKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    ECPrivateKey* impl = (ECPrivateKey*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_ECPrivateKeyValid(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key to PEM format */
    if (mbedtls_pk_write_key_pem(&impl->pk, buf, sizeof(buf)) != 0)
        OE_RAISE(OE_FAILURE);

    /* Handle case where caller's buffer is too small */
    {
        size_t size = OE_Strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        OE_Memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ECPublicKeyWritePEM(
    const OE_ECPublicKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    ECPublicKey* impl = (ECPublicKey*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_ECPublicKeyValid(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key to PEM format */
    if (mbedtls_pk_write_pubkey_pem(&impl->pk, buf, sizeof(buf)) != 0)
        OE_RAISE(OE_FAILURE);

    /* Handle case where caller's buffer is too small */
    {
        size_t size = OE_Strlen((char*)buf) + 1;

        if (*pemSize < size)
        {
            *pemSize = size;
            OE_RAISE(OE_BUFFER_TOO_SMALL);
        }

        OE_Memcpy(pemData, buf, size);
        *pemSize = size;
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ECPrivateKeyFree(OE_ECPrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        ECPrivateKey* impl = (ECPrivateKey*)key;

        if (!_ECPrivateKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _ECPrivateKeyFree(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ECPublicKeyFree(OE_ECPublicKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        ECPublicKey* impl = (ECPublicKey*)key;

        if (!_ECPublicKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _ECPublicKeyFree(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_ECPrivateKeySign(
    const OE_ECPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const ECPrivateKey* impl = (const ECPrivateKey*)privateKey;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t bufferSize = 0;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check parameters */
    if (!_ECPrivateKeyValid(impl) || !hashData || !hashSize || !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If signature buffer is null, then signature size must be zero */
    if (!signature && *signatureSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    // Sign the message. Note that bufferSize is an output parameter only.
    // MEBEDTLS provides no way to determine the size of the buffer up front.
    if (mbedtls_pk_sign(
            (mbedtls_pk_context*)&impl->pk,
            type,
            hashData,
            hashSize,
            buffer,
            &bufferSize,
            NULL,
            NULL) != 0)
    {
        OE_RAISE(OE_FAILURE);
    }

    // If signature buffer parameter is too small:
    if (*signatureSize < bufferSize)
    {
        *signatureSize = bufferSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    /* Copy result to output buffer */
    OE_Memcpy(signature, buffer, bufferSize);
    *signatureSize = bufferSize;

    result = OE_OK;

done:

    return result;
}

OE_Result OE_ECPublicKeyVerify(
    const OE_ECPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    const ECPublicKey* impl = (const ECPublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

OE_HostPrintf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
    /* Check for null parameters */
    if (!_ECPublicKeyValid(impl) || !hashData || !hashSize || !signature ||
        !signatureSize)
    {
        OE_RAISE(OE_INVALID_PARAMETER);
    }

    /* Verify the signature */
    if (mbedtls_pk_verify(
            (mbedtls_pk_context*)&impl->pk,
            type,
            hashData,
            hashSize,
            signature,
            signatureSize) != 0)
    {
        OE_RAISE(OE_VERIFY_FAILED);
    }

    result = OE_OK;

done:

    return result;
}

OE_Result OE_ECGenerateKeyPair(
    OE_ECType type,
    OE_ECPrivateKey* privateKey,
    OE_ECPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    ECPrivateKey* privateImpl = (ECPrivateKey*)privateKey;
    ECPublicKey* publicImpl = (ECPublicKey*)publicKey;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;
    int curve;
    const char* curveName;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    if (privateImpl)
        OE_Memset(privateImpl, 0, sizeof(*privateImpl));

    if (publicImpl)
        OE_Memset(publicImpl, 0, sizeof(*publicImpl));

    /* Check for invalid parameters */
    if (!privateImpl || !publicImpl)
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
    OE_CHECK(_ECPrivateKeyInitFrom(privateImpl, &pk));

    /* Initialize the public key parameter */
    OE_CHECK(OE_ECPublicKeyInitFrom(publicKey, &pk));
    
    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        if (_ECPrivateKeyValid(privateImpl))
            _ECPrivateKeyFree(privateImpl);

        if (_ECPublicKeyValid(publicImpl))
            _ECPublicKeyFree(publicImpl);
    }

    return result;
}

OE_Result OE_ECPublicKeyGetKeyBytes(
    const OE_ECPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    const ECPublicKey* impl = (const ECPublicKey*)publicKey;
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

        if (data == scratch)
            OE_RAISE(OE_BUFFER_TOO_SMALL);
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
    OE_Result result = OE_UNEXPECTED;
    const ECPublicKey* impl1 = (const ECPublicKey*)publicKey1;
    const ECPublicKey* impl2 = (const ECPublicKey*)publicKey2;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!_ECPublicKeyValid(impl1) || !_ECPublicKeyValid(impl2) || !equal)
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
