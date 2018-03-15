#include <assert.h>
#include <mbedtls/base64.h>
#include <mbedtls/ctr_drbg.h>
#include <mbedtls/entropy.h>
#include <mbedtls/pk.h>
#include <openenclave/bits/ec.h>
#include <openenclave/bits/rsa.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

/*
**==============================================================================
**
** Local definitions
**
**==============================================================================
*/

static OE_Result _LoadPrivateKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    mbedtls_pk_type_t type,
    mbedtls_pk_context** key)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_pk_context* pk = NULL;

    /* Initialize the key output parameter */
    if (key)
        *key = NULL;

    /* Check parameters */
    if (!pemData || pemSize == 0 || !key)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Allocate the key structure */
    if (!(pk = (mbedtls_pk_context*)malloc(sizeof(mbedtls_pk_context))))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Initialize the key structure */
    mbedtls_pk_init(pk);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_key(pk, pemData, pemSize, NULL, 0) != 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Check key type */
    if (mbedtls_pk_get_type(pk) != type)
    {
        result = OE_FAILURE;
        goto done;
    }

    *key = pk;
    pk = NULL;

    result = OE_OK;

done:

    if (pk)
        mbedtls_pk_free(pk);

    return result;
}

static OE_Result _LoadPublicKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    mbedtls_pk_type_t type,
    mbedtls_pk_context** key)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_pk_context* pk = NULL;

    /* Initialize the key output parameter */
    if (key)
        *key = NULL;

    /* Check parameters */
    if (!pemData || pemSize == 0 || !key)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Allocate the key structure */
    if (!(pk = (mbedtls_pk_context*)malloc(sizeof(mbedtls_pk_context))))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    /* Initialize the key structure */
    mbedtls_pk_init(pk);

    /* Parse PEM format into key structure */
    if (mbedtls_pk_parse_public_key(pk, pemData, pemSize) != 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Check key type */
    if (mbedtls_pk_get_type(pk) != type)
    {
        result = OE_FAILURE;
        goto done;
    }

    *key = pk;
    pk = NULL;

    result = OE_OK;

done:

    if (pk)
        mbedtls_pk_free(pk);

    return result;
}

typedef int (
    *WriteKeyFunc)(mbedtls_pk_context* ctx, unsigned char* buf, size_t size);

static int _WriteKey(
    mbedtls_pk_context* pk,
    WriteKeyFunc func,
    uint8_t** data,
    size_t* size)
{
    int ret = -1;
    const size_t DATA_SIZE = 1024;

    if (data)
        *data = NULL;

    if (size)
        *size = 0;

    /* Check parameters */
    if (!pk || !data || !size)
        goto done;

    /* Allocate a zero-filled the buffer */
    if (!(*data = (uint8_t*)calloc(*size = DATA_SIZE, sizeof(uint8_t))))
        goto done;

    /* Write the key (expand buffer size and retry if necessary) */
    for (;;)
    {
        int rc = (*func)(pk, *data, *size);

        /* Success */
        if (rc == 0)
            break;

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
                goto done;
            }

            *data = ptr;

            /* Zero-fill the buffer */
            memset(*data, 0, *size);
            continue;
        }

        /* Fail */
        goto done;
    }

    ret = 0;

done:
    return ret;
}

static void _Free(mbedtls_pk_context* key)
{
    if (key)
        mbedtls_pk_free(key);
}

static OE_Result _Sign(
    mbedtls_pk_context* privateKey,
    mbedtls_pk_type_t type,
    const OE_SHA256* hash,
    uint8_t** signature,
    size_t* signatureSize)
{
    OE_Result result = OE_UNEXPECTED;

    if (signature)
        *signature = NULL;

    if (signatureSize)
        *signatureSize = 0;

    /* Check for null parameters */
    if (!privateKey || !hash || !signature || !signatureSize)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Check key type */
    if (mbedtls_pk_get_type(privateKey) != type)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Allocate signature */
    if (!(*signature = (uint8_t*)malloc(MBEDTLS_MPI_MAX_SIZE)))
    {
        result = OE_OUT_OF_MEMORY;
        goto done;
    }

    size_t siglen = 0;

    /* Sign the message */
    if (mbedtls_pk_sign(
            (mbedtls_pk_context*)privateKey,
            MBEDTLS_MD_SHA256,
            hash->buf,
            0,
            *signature,
            &siglen,
            NULL,
            NULL) != 0)
    {
        result = OE_FAILURE;
        goto done;
    }

    if (siglen > MBEDTLS_MPI_MAX_SIZE)
    {
        result = OE_UNEXPECTED;
        goto done;
    }

    *signatureSize = siglen;

    result = OE_OK;

done:

    if (result != OE_OK)
    {
        if (signature && *signature)
            free(*signature);

        if (signatureSize)
            *signatureSize = 0;
    }

    return result;
}

static OE_Result _Verify(
    mbedtls_pk_context* publicKey,
    mbedtls_pk_type_t type,
    const OE_SHA256* hash,
    const uint8_t* signature,
    size_t signatureSize)
{
    OE_Result result = OE_UNEXPECTED;

    /* Check for null parameters */
    if (!publicKey || !hash || !signature || signatureSize == 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Check key type */
    if (mbedtls_pk_get_type(publicKey) != type)
    {
        result = OE_FAILURE;
        goto done;
    }

    /* Verify the signature */
    if (mbedtls_pk_verify(
            (mbedtls_pk_context*)publicKey,
            MBEDTLS_MD_SHA256,
            hash->buf,
            0,
            signature,
            signatureSize) != 0)
    {
        goto done;
    }

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

OE_Result OE_ECLoadPrivateKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_EC** key)
{
    return _LoadPrivateKeyFromPEM(
        pemData, pemSize, MBEDTLS_PK_ECKEY, (mbedtls_pk_context**)key);
}

OE_Result OE_ECLoadPublicKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_EC** key)
{
    return _LoadPublicKeyFromPEM(
        pemData, pemSize, MBEDTLS_PK_ECKEY, (mbedtls_pk_context**)key);
}

void OE_ECFree(OE_EC* key)
{
    _Free((mbedtls_pk_context*)key);
}

OE_Result OE_ECSign(
    OE_EC* privateKey,
    const OE_SHA256* hash,
    uint8_t** signature,
    size_t* signatureSize)
{
    return _Sign(
        (mbedtls_pk_context*)privateKey,
        MBEDTLS_PK_ECKEY,
        hash,
        signature,
        signatureSize);
}

OE_Result OE_ECVerify(
    OE_EC* publicKey,
    const OE_SHA256* hash,
    const uint8_t* signature,
    size_t signatureSize)
{
    return _Verify(
        (mbedtls_pk_context*)publicKey,
        MBEDTLS_PK_ECKEY,
        hash,
        signature,
        signatureSize);
}

OE_Result OE_ECGenerate(
    const char* curveName,
    OE_EC** privateKey,
    OE_EC** publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;
    uint8_t* data = NULL;
    size_t size;
    int curve;

    /* Initialize structures */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    if (privateKey)
        *privateKey = NULL;

    if (publicKey)
        *publicKey = NULL;

    /* Check for invalid parameters */
    if (!privateKey || !publicKey || !curveName)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Resolve the curveName parameter to an EC-curve identifier */
    {
        const mbedtls_ecp_curve_info* info;

        if (!(info = mbedtls_ecp_curve_info_from_name(curveName)))
        {
            result = OE_INVALID_PARAMETER;
            goto done;
        }

        curve = info->grp_id;
    }

    /* Set up an entropy source for reseeds below */
    if (mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Create key struct */
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_ECKEY)) != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Generate the EC key */
    if (mbedtls_ecp_gen_key(
            curve, mbedtls_pk_ec(pk), mbedtls_ctr_drbg_random, &ctr_drbg) != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize the private key parameter */
    {
        if (_WriteKey(&pk, mbedtls_pk_write_key_pem, &data, &size) != 0)
            goto done;

        if (OE_ECLoadPrivateKeyFromPEM(data, size, privateKey) != OE_OK)
            goto done;

        free(data);
        data = NULL;
    }

    /* Initialize the public key parameter */
    {
        if (_WriteKey(&pk, mbedtls_pk_write_pubkey_pem, &data, &size) != 0)
            goto done;

        if (OE_ECLoadPublicKeyFromPEM(data, size, publicKey) != OE_OK)
            goto done;

        free(data);
        data = NULL;
    }

    result = OE_OK;

done:

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&pk);

    if (data)
        free(data);

    if (result != OE_OK)
    {
        if (privateKey && *privateKey)
        {
            OE_ECFree(*privateKey);
            *privateKey = NULL;
        }

        if (publicKey && *publicKey)
        {
            OE_ECFree(*publicKey);
            *publicKey = NULL;
        }
    }

    return result;
}

/*
**==============================================================================
**
** Public RSA functions:
**
**==============================================================================
*/

OE_Result OE_RSALoadPrivateKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_RSA** key)
{
    return _LoadPrivateKeyFromPEM(
        pemData, pemSize, MBEDTLS_PK_RSA, (mbedtls_pk_context**)key);
}

OE_Result OE_RSALoadPublicKeyFromPEM(
    const void* pemData,
    size_t pemSize,
    OE_RSA** key)
{
    return _LoadPublicKeyFromPEM(
        pemData, pemSize, MBEDTLS_PK_RSA, (mbedtls_pk_context**)key);
}

void OE_RSAFree(OE_RSA* key)
{
    _Free((mbedtls_pk_context*)key);
}

OE_Result OE_RSASign(
    OE_RSA* privateKey,
    const OE_SHA256* hash,
    uint8_t** signature,
    size_t* signatureSize)
{
    return _Sign(
        (mbedtls_pk_context*)privateKey,
        MBEDTLS_PK_RSA,
        hash,
        signature,
        signatureSize);
}

OE_Result OE_RSAVerify(
    OE_RSA* publicKey,
    const OE_SHA256* hash,
    const uint8_t* signature,
    size_t signatureSize)
{
    return _Verify(
        (mbedtls_pk_context*)publicKey,
        MBEDTLS_PK_RSA,
        hash,
        signature,
        signatureSize);
}

OE_Result OE_RSAGenerate(
    uint64_t bits,
    uint64_t exponent,
    OE_RSA** privateKey,
    OE_RSA** publicKey)
{
    OE_Result result = OE_UNEXPECTED;
    mbedtls_entropy_context entropy;
    mbedtls_ctr_drbg_context ctr_drbg;
    mbedtls_pk_context pk;
    uint8_t* data = NULL;
    size_t size;

    /* Initialize structures */
    mbedtls_entropy_init(&entropy);
    mbedtls_ctr_drbg_init(&ctr_drbg);
    mbedtls_pk_init(&pk);

    if (privateKey)
        *privateKey = NULL;

    if (publicKey)
        *publicKey = NULL;

    /* Check for invalid parameters */
    if (!privateKey || !publicKey)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Check range of bits and exponent parameters */
    if (bits > OE_MAX_UINT || exponent > OE_MAX_INT)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Set up an entropy source for reseeds below */
    if (mbedtls_ctr_drbg_seed(
            &ctr_drbg, mbedtls_entropy_func, &entropy, NULL, 0) != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Create key struct */
    if (mbedtls_pk_setup(&pk, mbedtls_pk_info_from_type(MBEDTLS_PK_RSA)) != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Generate the RSA key */
    if (mbedtls_rsa_gen_key(
            mbedtls_pk_rsa(pk),
            mbedtls_ctr_drbg_random,
            &ctr_drbg,
            bits,
            exponent) != 0)
    {
        result = OE_INVALID_PARAMETER;
        goto done;
    }

    /* Initialize the private key parameter */
    {
        if (_WriteKey(&pk, mbedtls_pk_write_key_pem, &data, &size) != 0)
            goto done;

        if (OE_RSALoadPrivateKeyFromPEM(data, size, privateKey) != OE_OK)
            goto done;

        free(data);
        data = NULL;
    }

    /* Initialize the public key parameter */
    {
        if (_WriteKey(&pk, mbedtls_pk_write_pubkey_pem, &data, &size) != 0)
            goto done;

        if (OE_RSALoadPublicKeyFromPEM(data, size, publicKey) != OE_OK)
            goto done;

        free(data);
        data = NULL;
    }

    result = OE_OK;

done:

    mbedtls_entropy_free(&entropy);
    mbedtls_ctr_drbg_free(&ctr_drbg);
    mbedtls_pk_free(&pk);

    if (data)
        free(data);

    if (result != OE_OK)
    {
        if (privateKey && *privateKey)
        {
            OE_RSAFree(*privateKey);
            *privateKey = NULL;
        }

        if (publicKey && *publicKey)
        {
            OE_RSAFree(*publicKey);
            *publicKey = NULL;
        }
    }

    return result;
}
