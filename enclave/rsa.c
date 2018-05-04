// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include "rsa.h"
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <mbedtls/platform.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/hexdump.h>
#include <openenclave/bits/pem.h>
#include <openenclave/bits/raise.h>
#include <openenclave/bits/rsa.h>
#include "random.h"

// MBEDTLS has no mechanism for determining the size of the PEM buffer ahead
// of time, so we are forced to use a maximum buffer size.
#define OE_PEM_MAX_BYTES (16 * 1024)

/*
**==============================================================================
**
** Local definitions:
**
**==============================================================================
*/

/* Randomly generated magic number */
#define OE_RSA_PRIVATE_KEY_MAGIC 0xd48de5bae3994b41

typedef struct _RSAPrivateKey
{
    uint64_t magic;
    mbedtls_pk_context pk;
} RSAPrivateKey;

OE_STATIC_ASSERT(sizeof(RSAPrivateKey) <= sizeof(OE_RSAPrivateKey));

OE_INLINE bool _RSAPrivateKeyValid(const RSAPrivateKey* impl)
{
    return impl && impl->magic == OE_RSA_PRIVATE_KEY_MAGIC;
}

OE_INLINE void _RSAPrivateKeyInit(RSAPrivateKey* impl)
{
    impl->magic = OE_RSA_PRIVATE_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _RSAPrivateKeyFree(RSAPrivateKey* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(RSAPrivateKey));
    }
}

OE_INLINE void _RSAPrivateKeyClear(RSAPrivateKey* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(RSAPrivateKey));
}

OE_INLINE bool _RSAPublicKeyValid(const RSAPublicKey* impl)
{
    return impl && impl->magic == OE_RSA_PUBLIC_KEY_MAGIC;
}

OE_INLINE void _RSAPublicKeyInit(RSAPublicKey* impl)
{
    impl->magic = OE_RSA_PUBLIC_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _RSAPublicKeyFree(RSAPublicKey* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(RSAPublicKey));
    }
}

OE_INLINE void _RSAPublicKeyClear(RSAPublicKey* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(RSAPublicKey));
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

int OE_RSACopyKey(
    mbedtls_pk_context* dest,
    const mbedtls_pk_context* src,
    bool clearPrivateFields)
{
    int ret = -1;
    const mbedtls_pk_info_t* info;
    mbedtls_rsa_context* rsa;

    if (dest)
        mbedtls_pk_init(dest);

    /* Check for invalid parameters */
    if (!dest || !src)
        goto done;

    /* Lookup the RSA info */
    if (!(info = mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)))
        goto done;

    /* If not an RSA key */
    if (src->pk_info != info)
        goto done;

    /* Setup the context for this key type */
    if (mbedtls_pk_setup(dest, info) != 0)
        goto done;

    /* Get the context for this key type */
    if (!(rsa = dest->pk_ctx))
        goto done;

    /* Initialize the RSA key from the source */
    if (mbedtls_rsa_copy(rsa, mbedtls_pk_rsa(*src)) != 0)
        goto done;

    /* If public key, then clear private key fields */
    if (clearPrivateFields)
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

    ret = 0;

done:

    if (ret != 0)
        mbedtls_pk_free(dest);

    return ret;
}

static OE_Result _GetPublicKeyModulusOrExponent(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize,
    bool getModulus)
{
    const RSAPublicKey* impl = (const RSAPublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    size_t requiredSize;
    mbedtls_rsa_context* rsa;
    const mbedtls_mpi* mpi;

    /* Check for invalid parameters */
    if (!_RSAPublicKeyValid(impl) || !bufferSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then bufferSize must be zero */
    if (!buffer && *bufferSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the RSA context */
    if (!(rsa = impl->pk.pk_ctx))
        OE_RAISE(OE_FAILURE);

    /* Pick modulus or exponent */
    if (!(mpi = getModulus ? &rsa->N : &rsa->E))
        OE_RAISE(OE_FAILURE);

    /* Determine the required size in bytes */
    requiredSize = 1 + mbedtls_mpi_size(mpi);

    /* If buffer is null or not big enough */
    if (!buffer || (*bufferSize < requiredSize))
    {
        *bufferSize = requiredSize;
        OE_RAISE(OE_BUFFER_TOO_SMALL);
    }

    buffer[0] = 0x00;

    /* Copy key bytes to the caller's buffer */
    if (mbedtls_mpi_write_binary(mpi, buffer + 1, requiredSize - 1) != 0)
        OE_RAISE(OE_FAILURE);

    *bufferSize = requiredSize;

    result = OE_OK;

done:

    return result;
}

/*
**==============================================================================
**
** Public EC functions:
**
**==============================================================================
*/

OE_Result OE_RSAPrivateKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPrivateKey* privateKey)
{
    OE_Result result = OE_UNEXPECTED;
    RSAPrivateKey* impl = (RSAPrivateKey*)privateKey;

    /* Initialize the key */
    if (impl)
        _RSAPrivateKeyInit(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(&impl->pk, pemData, pemSize, NULL, 0) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain an RSA key */
    if (!OE_IsRSAKey(&impl->pk))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _RSAPrivateKeyFree(impl);

    return result;
}

OE_Result OE_RSAPublicKeyReadPEM(
    const uint8_t* pemData,
    size_t pemSize,
    OE_RSAPublicKey* publicKey)
{
    RSAPublicKey* impl = (RSAPublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (impl)
        _RSAPublicKeyInit(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Must have pemSize-1 non-zero characters followed by zero-terminator */
    if (OE_Strnlen((const char*)pemData, pemSize) != pemSize - 1)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(&impl->pk, pemData, pemSize) != 0)
        OE_RAISE(OE_FAILURE);

    /* Fail if PEM data did not contain an RSA key */
    if (!OE_IsRSAKey(&impl->pk))
        OE_RAISE(OE_FAILURE);

    result = OE_OK;

done:

    if (result != OE_OK)
        _RSAPublicKeyFree(impl);

    return result;
}

OE_Result OE_RSAPrivateKeyWritePEM(
    const OE_RSAPrivateKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    RSAPrivateKey* impl = (RSAPrivateKey*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_RSAPrivateKeyValid(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
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

OE_Result OE_RSAPublicKeyWritePEM(
    const OE_RSAPublicKey* key,
    uint8_t* pemData,
    size_t* pemSize)
{
    OE_Result result = OE_UNEXPECTED;
    RSAPublicKey* impl = (RSAPublicKey*)key;
    uint8_t buf[OE_PEM_MAX_BYTES];

    /* Check parameters */
    if (!_RSAPublicKeyValid(impl) || !pemSize)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* If buffer is null, then size must be zero */
    if (!pemData && *pemSize != 0)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Write the key (expand buffer size and retry if necessary) */
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

OE_Result OE_RSAPrivateKeyFree(OE_RSAPrivateKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        RSAPrivateKey* impl = (RSAPrivateKey*)key;

        if (!_RSAPrivateKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _RSAPrivateKeyFree(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_RSAPublicKeyFree(OE_RSAPublicKey* key)
{
    OE_Result result = OE_UNEXPECTED;

    if (key)
    {
        RSAPublicKey* impl = (RSAPublicKey*)key;

        if (!_RSAPublicKeyValid(impl))
            OE_RAISE(OE_INVALID_PARAMETER);

        _RSAPublicKeyFree(impl);
    }

    result = OE_OK;

done:
    return result;
}

OE_Result OE_RSAPrivateKeySign(
    const OE_RSAPrivateKey* privateKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    uint8_t* signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;
    const RSAPrivateKey* impl = (const RSAPrivateKey*)privateKey;
    uint8_t buffer[MBEDTLS_MPI_MAX_SIZE];
    size_t bufferSize = 0;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check parameters */
    if (!_RSAPrivateKeyValid(impl) || !hashData || !hashSize || !signatureSize)
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

OE_Result OE_RSAPublicKeyVerify(
    const OE_RSAPublicKey* publicKey,
    OE_HashType hashType,
    const void* hashData,
    size_t hashSize,
    const uint8_t* signature,
    size_t signatureSize)
{
    const RSAPublicKey* impl = (const RSAPublicKey*)publicKey;
    OE_Result result = OE_UNEXPECTED;
    mbedtls_md_type_t type = _MapHashType(hashType);

    /* Check for null parameters */
    if (!_RSAPublicKeyValid(impl) || !hashData || !hashSize || !signature ||
        !signatureSize)
        OE_RAISE(OE_INVALID_PARAMETER);

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

OE_Result OE_RSAGenerateKeyPair(
    uint64_t bits,
    uint64_t exponent,
    OE_RSAPrivateKey* privateKey,
    OE_RSAPublicKey* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    RSAPrivateKey* privateImpl = (RSAPrivateKey*)privateKey;
    RSAPublicKey* publicImpl = (RSAPublicKey*)publicKey;
    mbedtls_ctr_drbg_context* drbg;
    mbedtls_pk_context pk;

    /* Initialize structures */
    mbedtls_pk_init(&pk);

    _RSAPrivateKeyClear(privateImpl);
    _RSAPublicKeyClear(publicImpl);

    /* Check for invalid parameters */
    if (!privateImpl || !publicImpl)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Check range of bits and exponent parameters */
    if (bits > OE_MAX_UINT || exponent > OE_MAX_INT)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Get the random number generator */
    if (!(drbg = OE_MBEDTLS_GetDrbg()))
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
    {
        if (OE_RSACopyKey(&privateImpl->pk, &pk, false) != 0)
            OE_RAISE(OE_FAILURE);

        privateImpl->magic = OE_RSA_PRIVATE_KEY_MAGIC;
    }

    /* Initialize the public key parameter */
    {
        if (OE_RSACopyKey(&publicImpl->pk, &pk, true) != 0)
            OE_RAISE(OE_FAILURE);

        publicImpl->magic = OE_RSA_PUBLIC_KEY_MAGIC;
    }

    result = OE_OK;

done:

    mbedtls_pk_free(&pk);

    if (result != OE_OK)
    {
        OE_RSAPrivateKeyFree(privateKey);
        OE_RSAPublicKeyFree(publicKey);
    }

    return result;
}

OE_Result OE_RSAPublicKeyGetModulus(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyModulusOrExponent(publicKey, buffer, bufferSize, true);
}

OE_Result OE_RSAPublicKeyGetExponent(
    const OE_RSAPublicKey* publicKey,
    uint8_t* buffer,
    size_t* bufferSize)
{
    return _GetPublicKeyModulusOrExponent(publicKey, buffer, bufferSize, false);
}

OE_Result OE_RSAPublicKeyEqual( 
    const OE_RSAPublicKey* publicKey1,
    const OE_RSAPublicKey* publicKey2,
    bool* equal)
{
    OE_Result result = OE_UNEXPECTED;
    const RSAPublicKey* impl1 = (const RSAPublicKey*)publicKey1;
    const RSAPublicKey* impl2 = (const RSAPublicKey*)publicKey2;

    if (equal)
        *equal = false;

    /* Reject bad parameters */
    if (!_RSAPublicKeyValid(impl1) || !_RSAPublicKeyValid(impl2) || !equal)
        OE_RAISE(OE_INVALID_PARAMETER);

    /* Compare the exponent and modulus */
    {
        const mbedtls_rsa_context* rsa1 = impl1->pk.pk_ctx;
        const mbedtls_rsa_context* rsa2 = impl2->pk.pk_ctx;

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
