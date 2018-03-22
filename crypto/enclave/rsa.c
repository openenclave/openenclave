// Copyright (c) Microsoft Corporation. All rights reserved.
// Licensed under the MIT License.

#include <assert.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <openenclave/bits/ec.h>
#include <openenclave/bits/enclavelibc.h>
#include <openenclave/bits/rsa.h>
#include <openenclave/bits/trace.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "../util.h"

/*
**==============================================================================
**
** Local definitions
**
**==============================================================================
*/

#define OE_RSA_KEY_MAGIC 0xb375208a5590eedb

typedef struct _OE_RSA_KEY_IMPL
{
    uint64_t magic;
    mbedtls_pk_context pk;
}
OE_RSA_KEY_IMPL;

OE_STATIC_ASSERT(sizeof(OE_RSA_KEY_IMPL) <= sizeof(OE_RSA_KEY));

OE_INLINE bool _ValidImpl(const OE_RSA_KEY_IMPL* impl)
{
    return impl && impl->magic == OE_RSA_KEY_MAGIC;
}

OE_INLINE void _InitImpl(OE_RSA_KEY_IMPL* impl)
{
    impl->magic = OE_RSA_KEY_MAGIC;
    mbedtls_pk_init(&impl->pk);
}

OE_INLINE void _FreeImpl(OE_RSA_KEY_IMPL* impl)
{
    if (impl)
    {
        mbedtls_pk_free(&impl->pk);
        OE_Memset(impl, 0, sizeof(OE_RSA_KEY_IMPL));
    }
}

OE_INLINE void _ClearImpl(OE_RSA_KEY_IMPL* impl)
{
    if (impl)
        OE_Memset(impl, 0, sizeof(OE_RSA_KEY_IMPL));
}

/*
**==============================================================================
**
** Public EC functions:
**
**==============================================================================
*/

OE_Result OE_RSAReadPrivateKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_RSA_KEY* privateKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)privateKey;

    /* Initialize the key */
    if (impl)
        _InitImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    OE_TRY(OE_CheckForNullTerminator(pemData, pemSize));

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(&impl->pk, pemData, pemSize, NULL, 0) != 0)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

OE_CATCH:

    if (result != OE_OK)
        _FreeImpl(impl);

    return result;
}

OE_Result OE_RSAReadPublicKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_RSA_KEY* publicKey)
{
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    /* Initialize the key */
    if (impl)
        _InitImpl(impl);

    /* Check parameters */
    if (!pemData || pemSize == 0 || !impl)
        OE_THROW(OE_INVALID_PARAMETER);

    /* The position of the null terminator must be the last byte */
    OE_TRY(OE_CheckForNullTerminator(pemData, pemSize));

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(&impl->pk, pemData, pemSize) != 0)
        OE_THROW(OE_FAILURE);

    result = OE_OK;

OE_CATCH:

    if (result != OE_OK)
        _FreeImpl(impl);

    return result;
}

OE_Result OE_RSAWritePrivateKeyToPEM(
    const OE_RSA_KEY* key, 
    void** data, 
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;
    const size_t DATA_SIZE = 1024;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!_ValidImpl(impl) || !data || !size)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Set the initial size of the buffer */
    *size = DATA_SIZE;

    /* Allocate a zero-filled the buffer */
    if (!(*data = (uint8_t*)calloc(*size, sizeof(uint8_t))))
        OE_THROW(OE_OUT_OF_MEMORY);

    /* Write the key (expand buffer size and retry if necessary) */
    for (;;)
    {
        int rc = mbedtls_pk_write_key_pem(&impl->pk, *data, *size);

        /* Success */
        if (rc == 0)
        {
            *size = OE_Strlen((char*)*data) + 1;
            break;
        }

        /* Expand the buffer if it was not big enough */
        if (rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
        {
            void* ptr;

            /* Double the size */
            *size *= 2;

            /* Expand the buffer */
            if (!(ptr = (uint8_t*)realloc(*data, *size)))
            {
                free(*data);
                *data = NULL;
                *size = 0;
                OE_THROW(OE_OUT_OF_MEMORY);
            }

            *data = ptr;

            /* Zero-fill the buffer */
            memset(*data, 0, *size);
            continue;
        }

        /* Fail */
        OE_THROW(OE_FAILURE);
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

OE_Result OE_RSAWritePublicKeyToPEM(
    const OE_RSA_KEY* key, 
    void** data, 
    size_t* size)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;
    const size_t DATA_SIZE = 1024;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!_ValidImpl(impl) || !data || !size)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Set the initial size of the buffer */
    *size = DATA_SIZE;

    /* Allocate a zero-filled the buffer */
    if (!(*data = (uint8_t*)calloc(*size, sizeof(uint8_t))))
        OE_THROW(OE_OUT_OF_MEMORY);

    /* Write the key (expand buffer size and retry if necessary) */
    for (;;)
    {
        int rc = mbedtls_pk_write_pubkey_pem(&impl->pk, *data, *size);

        /* Success */
        if (rc == 0)
        {
            *size = OE_Strlen((char*)*data) + 1;
            break;
        }

        /* Expand the buffer if it was not big enough */
        if (rc == MBEDTLS_ERR_BASE64_BUFFER_TOO_SMALL)
        {
            void* ptr;

            /* Double the size */
            *size *= 2;

            /* Expand the buffer */
            if (!(ptr = (uint8_t*)realloc(*data, *size)))
            {
                free(*data);
                *data = NULL;
                *size = 0;
                OE_THROW(OE_OUT_OF_MEMORY);
            }

            *data = ptr;

            /* Zero-fill the buffer */
            memset(*data, 0, *size);
            continue;
        }

        /* Fail */
        OE_THROW(OE_FAILURE);
    }

    result = OE_OK;

OE_CATCH:
    return result;
}

OE_Result OE_RSAFree(OE_RSA_KEY* key)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* impl = (OE_RSA_KEY_IMPL*)key;

    if (!_ValidImpl(impl))
        OE_THROW(OE_INVALID_PARAMETER);

    _FreeImpl(impl);

    result = OE_OK;

OE_CATCH:
    return result;
}

OE_Result OE_RSASign(
    const OE_RSA_KEY* privateKey,
    const OE_SHA256* hash,
    uint8_t** signature,
    size_t* signatureSize)
{
    const OE_RSA_KEY_IMPL* impl = (const OE_RSA_KEY_IMPL*)privateKey;
    OE_Result result = OE_UNEXPECTED;

    if (signature)
        *signature = NULL;

    if (signatureSize)
        *signatureSize = 0;

    /* Check for null parameters */
    if (!_ValidImpl(impl) || !hash || !signature || !signatureSize)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Allocate signature */
    if (!(*signature = (uint8_t*)malloc(MBEDTLS_MPI_MAX_SIZE)))
        OE_THROW(OE_OUT_OF_MEMORY);

    size_t siglen = 0;

    /* Sign the message */
    if (mbedtls_pk_sign(
            (mbedtls_pk_context*)&impl->pk,
            MBEDTLS_MD_SHA256,
            hash->buf,
            0,
            *signature,
            &siglen,
            NULL,
            NULL) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    if (siglen > MBEDTLS_MPI_MAX_SIZE)
        OE_THROW(OE_FAILURE);

    *signatureSize = siglen;

    result = OE_OK;

OE_CATCH:

    if (result != OE_OK)
    {
        if (signature && *signature)
            free(*signature);

        if (signatureSize)
            *signatureSize = 0;
    }

    return result;
}

OE_Result OE_RSAVerify(
    const OE_RSA_KEY* publicKey,
    const OE_SHA256* hash,
    const uint8_t* signature,
    size_t signatureSize)
{
    const OE_RSA_KEY_IMPL* impl = (const OE_RSA_KEY_IMPL*)publicKey;
    OE_Result result = OE_UNEXPECTED;

    /* Check for null parameters */
    if (!_ValidImpl(impl) || !hash || !signature || signatureSize == 0)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Verify the signature */
    if (mbedtls_pk_verify(
            (mbedtls_pk_context*)&impl->pk,
            MBEDTLS_MD_SHA256,
            hash->buf,
            0,
            signature,
            signatureSize) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    result = OE_OK;

OE_CATCH:

    return result;
}

OE_Result OE_RSAGenerate(
    uint64_t bits,
    uint64_t exponent,
    OE_RSA_KEY* privateKey,
    OE_RSA_KEY* publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    OE_RSA_KEY_IMPL* privateImpl = (OE_RSA_KEY_IMPL*)privateKey;
    OE_RSA_KEY_IMPL* publicImpl = (OE_RSA_KEY_IMPL*)publicKey;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;
    uint8_t* data = NULL;
    size_t size;

    /* Initialize structures */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    _ClearImpl(privateImpl);
    _ClearImpl(publicImpl);

    /* Check for invalid parameters */
    if (!privateImpl || !publicImpl)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Check range of bits and exponent parameters */
    if (bits > OE_MAX_UINT || exponent > OE_MAX_INT)
        OE_THROW(OE_INVALID_PARAMETER);

    /* Set up an entropy source for reseeds below */
    if (mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    /* Create key struct */
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    /* Generate the RSA key */
    if (mbedtls_rsa_gen_key(
            mbedtls_pk_rsa(pk),
            mbedtls_ctr_drbg_random,
            &ctr_drbg,
            bits,
            exponent) != 0)
    {
        OE_THROW(OE_FAILURE);
    }

    /* Initialize the private key parameter */
    {
        OE_RSA_KEY_IMPL dummy;

        dummy.magic = OE_RSA_KEY_MAGIC;
        dummy.pk = pk;
        OE_TRY(OE_RSAWritePrivateKeyToPEM(
            (OE_RSA_KEY*)&dummy, (void**)&data, &size));
        pk = dummy.pk;

        OE_TRY(OE_RSAReadPrivateKeyFromPEM(data, size, privateKey));
        free(data);
        data = NULL;
    }

    /* Initialize the public key parameter */
    {
        OE_RSA_KEY_IMPL dummy;

        dummy.magic = OE_RSA_KEY_MAGIC;
        dummy.pk = pk;
        OE_TRY(OE_RSAWritePublicKeyToPEM(
            (OE_RSA_KEY*)&dummy, (void**)&data, &size));
        pk = dummy.pk;

        OE_TRY(OE_RSAReadPublicKeyFromPEM(data, size, publicKey));
        free(data);
        data = NULL;
    }

    result = OE_OK;

OE_CATCH:

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&pk);

    if (data)
        free(data);

    if (result != OE_OK)
    {
        if (_ValidImpl(privateImpl))
            OE_RSAFree(privateKey);

        if (_ValidImpl(publicImpl))
            OE_RSAFree(publicKey);
    }

    return result;
}
